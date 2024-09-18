package exporters

func getLabels(ignoreIndividuals bool, version string) ([]string, []string, []string, []string) {
	var serverHeaderClientLabels []string
	var serverHeaderClientLabelColumns []string
	var serverHeaderRoutingLabels []string
	var serverHeaderRoutingLabelColumns []string

	if version == "2.3" {
		if ignoreIndividuals {
			serverHeaderClientLabels = []string{"status_path", "common_name"}
			serverHeaderClientLabelColumns = []string{"Common Name"}
			serverHeaderRoutingLabels = []string{"status_path", "common_name"}
			serverHeaderRoutingLabelColumns = []string{"Common Name"}
		} else {
			serverHeaderClientLabels = []string{"status_path", "common_name", "connection_time", "real_address", "virtual_address", "username"}
			serverHeaderClientLabelColumns = []string{"Common Name", "Connected Since (time_t)", "Real Address", "Virtual Address", "Username"}
			serverHeaderRoutingLabels = []string{"status_path", "common_name", "real_address", "virtual_address"}
			serverHeaderRoutingLabelColumns = []string{"Common Name", "Real Address", "Virtual Address"}
		}
	}

	if version == "2.4" {
		if ignoreIndividuals {
			serverHeaderClientLabels = []string{"status_path", "common_name"}
			serverHeaderClientLabelColumns = []string{"Common Name"}
			serverHeaderRoutingLabels = []string{"status_path", "common_name"}
			serverHeaderRoutingLabelColumns = []string{"Common Name"}
		} else {
			serverHeaderClientLabels = []string{"status_path", "common_name", "connection_time", "real_address"}
			serverHeaderClientLabelColumns = []string{"Common Name", "Connected Since", "Real Address"}
			serverHeaderRoutingLabels = []string{"status_path", "common_name", "real_address", "virtual_address"}
			serverHeaderRoutingLabelColumns = []string{"Common Name", "Real Address", "Virtual Address"}
		}
	}
	return serverHeaderClientLabels, serverHeaderClientLabelColumns, serverHeaderRoutingLabels, serverHeaderRoutingLabelColumns
}
