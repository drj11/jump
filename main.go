package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/codegangsta/cli"
	"github.com/olekukonko/tablewriter"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/ec2"
)

func ShowInstances(instances []*Instance) {
	table := tablewriter.NewWriter(os.Stderr)
	table.SetAlignment(tablewriter.ALIGN_RIGHT)
	table.SetHeader([]string{
		"N", "ID", "Name", "S", "Private", "Launch",
		"ICMP", "SSH", "HTTP", "HTTPS"})

	for n, i := range instances {
		row := []string{
			fmt.Sprint(n), i.InstanceID[2:], i.Name(), i.PrettyState(),
			i.PrivateIP, fmtDuration(i.Up),
			(<-i.ICMPPing).String(),
			(<-i.SSHPing).String(),
			(<-i.HTTPPing).String(),
			(<-i.HTTPSPing).String(),
		}
		table.Append(row)
	}

	table.Render()
}

func GetInstanceFromUser(max int) int {
	s := bufio.NewScanner(os.Stdin)
	if !s.Scan() {
		// User closed stdin before we read anything
		os.Exit(1)
	}
	if s.Err() != nil {
		log.Fatalln("Error reading stdin:", s.Err())
	}
	var n int
	_, err := fmt.Sscan(s.Text(), &n)
	if err != nil {
		log.Fatalln("Unrecognised input:", s.Text())
	}
	if n >= max {
		log.Fatalln("%d is not a valid instance", n)
	}
	return n
}

func InvokeSSH(cliArgs cli.Args, bastion string, instance *Instance, n int) {
	fmt.Fprintf(os.Stderr, "\n-- [ Connecting to %v (%v:%v) ] --\n\n",
		instance.PrivateIP, instance.Name(), n)

	args := []string{"/usr/bin/ssh"}

	if bastion != "" {
		format := `ProxyCommand=ssh %v %v %%h %%p`
		netCat := "ncat" // TODO(pwaller): automatically determine netcat binary
		proxyCommand := fmt.Sprintf(format, bastion, netCat)
		args = append(args, "-o", proxyCommand)
	}

	// Enable the user to specify arguments to the left and right of the host.
	// left, right := BreakArgsBySeparator(cliArgs)
	// args = append(args, left...)
	args = append(args, instance.PrivateIP)
	args = append(args, cliArgs...)

	log.Printf("exec: %q", args)

	err := syscall.Exec("/usr/bin/ssh", args, os.Environ())
	if err != nil {
		log.Fatalln("Failed to exec:", err)
	}
}

func CursorUp(n int) {
	fmt.Fprint(os.Stderr, "[", n, "F")
}
func ClearToEndOfScreen() {
	fmt.Fprint(os.Stderr, "[", "J")
}

func JumpTo(c *cli.Context, bastion string, client *ec2.EC2) {

	ec2Instances, err := client.DescribeInstances(&ec2.DescribeInstancesInput{})
	if err != nil {
		log.Fatal("DescribeInstances error:", err)
	}

	// Do this after querying the AWS endpoint (otherwise vulnerable to MITM.)
	ConfigureHTTP(false)

	instances := InstancesFromEC2Result(ec2Instances)
	ShowInstances(instances)

	n := c.Int("n")
	if !c.IsSet("n") {
		n = GetInstanceFromUser(len(instances))
	}

	// +1 to account for final newline.
	CursorUp(len(instances) + N_TABLE_DECORATIONS + 1)
	ClearToEndOfScreen()

	InvokeSSH(c.Args(), bastion, instances[n], n)
}

func Watch(client *ec2.EC2) {
	c := ec2.New(nil)

	finish := make(chan struct{})
	go func() {
		defer close(finish)
		// Await stdin closure
		io.Copy(ioutil.Discard, os.Stdin)
	}()

	goUp := func() {}

	for {
		queryStart := time.Now()
		ConfigureHTTP(true)

		ec2Instances, err := c.DescribeInstances(&ec2.DescribeInstancesInput{})
		if err != nil {
			log.Fatal("DescribeInstances error:", err)
		}

		ConfigureHTTP(false)

		instances := InstancesFromEC2Result(ec2Instances)

		goUp()

		ShowInstances(instances)

		queryDuration := time.Since(queryStart)

		select {
		case <-time.After(1*time.Second - queryDuration):
		case <-finish:
			return
		}
		goUp = func() { CursorUp(len(instances) + N_TABLE_DECORATIONS) }
	}

}

const N_TABLE_DECORATIONS = 4

func addAgentAuth(auths []ssh.AuthMethod) []ssh.AuthMethod {
	if sock := os.Getenv("SSH_AUTH_SOCK"); len(sock) > 0 {
		if agconn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(agconn)
			auths = append(auths, ssh.PublicKeysCallback(ag.Signers))
		}
	}
	return auths
}

func LoadKey() (ssh.Signer, error) {
	fd, err := os.Open(os.ExpandEnv("$HOME/.ssh/id_rsa"))
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	pemBytes, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	log.Printf("Got %v pembytes", len(pemBytes))

	return ssh.ParsePrivateKey(pemBytes)
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "bastion, b",
			Usage:  "bastion host to use",
			EnvVar: "JUMP_BASTION",
			Value:  "<unset>",
		},
		cli.IntFlag{
			Name:  "instance-index, n",
			Usage: "go straight to host n",
		},
	}

	app.Action = func(c *cli.Context) {
		auths := []ssh.AuthMethod{}
		auths = addAgentAuth(auths)

		config := &ssh.ClientConfig{}
		config.SetDefaults()

		config.User = "pwaller"
		config.Auth = auths

		bastion := c.String("bastion")

		// TODO(pwaller): configurable SSH port
		conn, err := ssh.Dial("tcp", bastion+":22", config)
		if err != nil {
			log.Fatalf("Failed to connect to bastion %q: %v", bastion, err)
		}

		t := &http.Transport{
			// Use the ssh connection to dial remotes
			Dial: conn.Dial,
		}

		http.DefaultClient.Transport = t

		region, err := ThisRegion()
		if err != nil {
			log.Fatalln("Unable to determine bastion region")
		}

		awsConfig := *aws.DefaultConfig
		awsConfig.HTTPClient = http.DefaultClient
		awsConfig.Region = region

		client := ec2.New(&awsConfig)

		JumpTo(c, bastion, client)
	}

	app.Commands = []cli.Command{
		{
			Name: "bastion",
			Action: func(c *cli.Context) {
				log.Printf("Foo!")
			},
		},
	}

	app.RunAndExitOnError()
	return

	// if os.Getenv("SSH_AUTH_SOCK") == "" {
	// 	fmt.Fprintln(os.Stderr, "[41;1mWarning: agent forwarding not enabled[K[m")
	// }

	// client := ec2.New(nil)

	// if len(os.Args) > 1 && os.Args[1] == "@" {
	// 	Watch(client)
	// 	return
	// }

	// JumpTo("", client)
}
