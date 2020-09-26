package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/lair-framework/go-nmap"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("%s <nmap xml output> <folder to output> [json mapping file of ip to hostname]", os.Args[0])
	}

	wholeFile, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}

	n, err := nmap.Parse(wholeFile)
	if err != nil {
		log.Fatalln(err)
	}

	domainsMap := make(map[string]string)
	if len(os.Args) > 3 {

		b, err := ioutil.ReadFile(os.Args[3])
		if err != nil {
			log.Fatalln(err)
		}

		err = json.Unmarshal(b, &domainsMap)
		if err != nil {
			log.Fatalln(err)
		}

	}

	log.Println("Parsed ", len(n.Hosts), "hosts")

	output := make(map[string]map[string]bool)

	re := regexp.MustCompile(`DNS:(.*?), `)

	nmapCertDNS := make(map[string]bool)

	for _, v := range n.Hosts {
		for _, ports := range v.Ports {
			if ports.State.State == "open" {

				for _, z := range ports.Scripts { // Note for future me, this is unbelievably dumb. I know. Golang cant marshal XML to a map... so nested l_oo_p brother
					if z.Id == "ssl-cert" {
						segs := re.FindAllStringSubmatch(z.Output, -1)
						if segs != nil {
							for _, segment := range segs {

								nmapCertDNS[strings.ToLower(segment[1])] = true

							}

						}

					}
				}

				os.MkdirAll(fmt.Sprintf("%s/%d", os.Args[2], ports.PortId), 0744)

				filename := strings.ReplaceAll(ports.Service.Product, "/", "_")
				filename = strings.ReplaceAll(filename, " ", "_")
				if ports.Service.Product == "" {
					filename = "UnknownService"
				}

				path := fmt.Sprintf("%s/%d/%s-%s", os.Args[2], ports.PortId, ports.Service.Name, filename)

				if _, ok := output[path]; !ok {
					output[path] = make(map[string]bool)
				}

				for _, addr := range v.Addresses {

					address := addr.Addr
					if domain, ok := domainsMap[addr.Addr]; ok {
						address += "," + domain
					}

					output[path][address] = true
				}
			}
		}
	}

	for path, addresses := range output {
		f, err := os.OpenFile(path,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
			continue
		}
		defer f.Close()

		for address := range addresses {
			if _, err := f.WriteString(address + "\n"); err != nil {
				log.Println(err)
			}
		}
	}

	f, err := os.OpenFile("nmap_discovered_domains",
		os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	for v := range nmapCertDNS {
		if _, err := f.WriteString(v + "\n"); err != nil {
			log.Println(err)
		}
	}
}
