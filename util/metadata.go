package util

// Metadata represents info about the current instance.
// Some info is only available on VMs or CloudRun.
type Metadata struct {
	Instance struct {
		Attributes struct {
			// Only GKE
			ClusterLocation string
			ClusterName     string
			ClusterUid      string

			// Only GCP
			// Full authorized_hosts with \n separators
			SSHKeys string
		}

		// Only GCP
		// cpuPlatform
		// description
		// disks
		// guestAttributes
		// image
		// licences
		// machineType projects/NUMBER/machineTypes/NAME
		// maintenanceEvent

		//     "hostname": "gke-CLUSTER_NAME-pool-1-1b6cad60-1l3a.c.costin-asm1.internal",
		// This is the FQDN hostname of the node !
		Hostname string
		ID       int

		// Local part of the hostname.
		Name string

		Zone string

		// Default is present and the service account running the node/VM
		ServiceAccounts map[string]struct {
			Aliases []string // "default"
			Email   string   // Based on annotation on the KSA
			Scopes  []string
		}

		NetworkInterfaces map[string]struct {
			IPV6s string

			// Only GCP
			AccessConfigs struct {
				ExternalIP string
				Type       string // ONE_TO_ONE_NAT
			}
			Gateway           string
			IP                string
			Mac               string
			Mtu               string
			Network           string // projects/NUMBER/network/NAME
			Subnetmask        string
			TargetInstanceIps []string
			DNSServers        []string
		}
		Tags []string
	}

	Project struct {
		NumericProjectId int
		ProjectId        string

		// Only on GCP
		Attributes map[string]string
		// 	SSHKeys2 string
		//	SSHKeys string
	}
}
