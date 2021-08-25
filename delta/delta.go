package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gepis/ps"
	"github.com/sirupsen/logrus"
)

func main() {
	var (
		descriptors []string
		pidsList    []string
		data        [][]string
		err         error

		pids         = flag.String("pids", "", "comma separated list of process IDs to retrieve")
		format       = flag.String("format", "", "ps(1) AIX format comma-separated string")
		list         = flag.Bool("list", false, "list all supported descriptors")
		join         = flag.Bool("join", false, "join namespace of provided pids (containers)")
		fillMappings = flag.Bool("fill-mappings", false, "fill the UID and GID mappings with the current user namespace")
	)

	flag.Parse()

	if *fillMappings && !*join {
		fmt.Fprintln(os.Stderr, "-fill-mappings requires -join")
		os.Exit(1)
	}

	if *list {
		fmt.Println(strings.Join(ps.ListDescriptors(), ", "))
		return
	}

	if *format != "" {
		descriptors = strings.Split(*format, ",")
	}

	if *pids != "" {
		pidsList = strings.Split(*pids, ",")
	}

	if len(pidsList) > 0 {
		opts := ps.JoinNamespaceOpts{FillMappings: *fillMappings}

		if *join {
			data, err = ps.JoinNamespaceAndProcessInfoByPidsWithOptions(pidsList, descriptors, &opts)
		} else {
			data, err = ps.ProcessInfoByPids(pidsList, descriptors)
		}

		if err != nil {
			logrus.Panic(err)
		}
	} else {
		data, err = ps.ProcessInfo(descriptors)
		if err != nil {
			logrus.Panic(err)
		}
	}

	tw := tabwriter.NewWriter(os.Stdout, 5, 1, 3, ' ', 0)
	for _, d := range data {
		fmt.Fprintln(tw, strings.Join(d, "\t"))
	}

	tw.Flush()
}
