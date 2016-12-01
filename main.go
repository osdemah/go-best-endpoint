package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/jasonlvhit/gocron"
	"github.com/lair-framework/go-nmap"
)

// Represents endpoint performance
type HostPerformance struct {
	Latency	uint64
	State	string
}

// Represents endpoint
type EndpointAddress struct {
	Host string
	Port string
}

const MicrosecondsInSecond = uint64(1000000)

func ChooseBestEndpoint(endpoints []EndpointAddress) (*EndpointAddress, error){
	// Chooses best endpoint from given endpoints.
	if len(endpoints) > 0 {
		bestEndpoint := &endpoints[0]
		bestScore := Heuristic(ScanHost(&endpoints[0]))
		for i := 1; i < len(endpoints); i++ {
			endpoint := &endpoints[i]
			score := Heuristic(ScanHost(endpoint))
			if score < bestScore {
				bestScore = score
				bestEndpoint = endpoint
			}
		}
		return bestEndpoint, nil
	}
	return nil, errors.New("No endpoint available!");
}

func ScanHost(endpoint *EndpointAddress) *HostPerformance {
	// Call nmap to scan given endpoint and output the results in XML format
	cmd := exec.Command("nmap", endpoint.Host, "-oX", "-", "-p" , endpoint.Port)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// Parse nmap XML output
	run, err := nmap.Parse(out.Bytes())
	if len(run.Hosts) > 0 {
		hostPerformance := &HostPerformance{}
		hostPerformance.State = run.Hosts[0].Ports[0].State.State

		// Find line containing the rtt.
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(line, "<times") {
				time := &nmap.Times{}
				err = xml.Unmarshal([]byte(line), time)
				if err != nil {
					log.Fatal(err)
				}
				hostPerformance.Latency, _ = strconv.ParseUint(time.SRTT, 10, 64)
			}
		}
		// Print the results
		fmt.Println("Endpoint:", endpoint.Host + ":" + endpoint.Port, "Latency(in us):",
			hostPerformance.Latency, "Status:", hostPerformance.State)
		return hostPerformance
	}
	// Invalid host is like 100 seconds of latency!
	fmt.Println("Endpoint:", endpoint.Host + ":" + endpoint.Port , "Status:", "Unavailable")
	return &HostPerformance{100 * MicrosecondsInSecond, "close"}
}

func Heuristic(hostPerformance *HostPerformance) uint64 {
	// Find that port is open or not.
	state := uint64(1)
	if strings.Compare(hostPerformance.State, "open") == 0 {
		state = 0
	}
	// Not open port is like 10 seconds of latency!
	return hostPerformance.Latency + state * 10 * MicrosecondsInSecond
}

func PrintBestEndpoint(endpoints []EndpointAddress) {
	fmt.Println("Start scanning of endpoints.")
	bestEndpoint, _ := ChooseBestEndpoint(endpoints)
	fmt.Println("The best endpoint is ", bestEndpoint.Host + ":" + bestEndpoint.Port)
}

func main() {
	// read the config file
	in, err := ioutil.ReadFile("endpoints.conf")
	if err != nil {
		log.Fatalln("Error reading file:", err)
	}

	// Parse config file
	endpointScanner := &EndpointsScanner{}
	if err := proto.UnmarshalText(string(in), endpointScanner); err != nil {
		log.Fatalln("Failed to parse endpoint scanner:", err)
	}

	// Extract the endpoints from parsed file
	var endpoints []EndpointAddress
	for i := 0; i < len(endpointScanner.Endpoints); i++{
		endpoint := EndpointAddress{}
		endpoint.Host = *(endpointScanner.Endpoints[i].Host)
		endpoint.Port = strconv.FormatUint(uint64(*(endpointScanner.Endpoints[i].Port)), 10)
		endpoints = append(endpoints, endpoint)
	}

	// Initial check of endpoints (For someone who cant wait up to next scheduled job!)
	PrintBestEndpoint(endpoints)

	// Create and start cron job.
	periodType := *endpointScanner.Period.PeriodType
	period := *endpointScanner.Period.Period
	scheduler := gocron.NewScheduler()
	if (periodType == Period_DAYS) {
		if period == 1 {
			scheduler.Every(period).Day().Do(PrintBestEndpoint, endpoints)
		} else {
			scheduler.Every(period).Days().Do(PrintBestEndpoint, endpoints)
		}
	} else if (periodType == Period_HOURS) {
		if period == 1 {
			scheduler.Every(period).Hour().Do(PrintBestEndpoint, endpoints)
		} else {
			scheduler.Every(period).Hours().Do(PrintBestEndpoint, endpoints)
		}
	} else if (periodType == Period_MINUTES) {
		if period == 1 {
			scheduler.Every(period).Minute().Do(PrintBestEndpoint, endpoints)
		} else {
			scheduler.Every(period).Minutes().Do(PrintBestEndpoint, endpoints)
		}
	} else if (periodType == Period_SECONDS) {
		if period == 1 {
			scheduler.Every(period).Second().Do(PrintBestEndpoint, endpoints)
		} else {
			scheduler.Every(period).Seconds().Do(PrintBestEndpoint, endpoints)
		}
	}
	<- scheduler.Start()
}
