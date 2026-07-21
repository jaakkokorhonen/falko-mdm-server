resource "google_compute_network" "vpc_network" {
  # checkov:skip=CKV2_GCP_18:Firewall rules are not needed as this VPC is strictly used for Serverless VPC Access egress routing
  project                 = var.gcp_project_id
  name                    = "falko-mdm-vpc"
  auto_create_subnetworks = false
}

# 2. Aliverkko, johon Serverless VPC Access liitetään
resource "google_compute_subnetwork" "subnet" {
  # checkov:skip=CKV_GCP_26:VPC Flow Logs are disabled to avoid excessive log generation and storage costs for a simple serverless connector egress VPC
  project                  = var.gcp_project_id
  name                     = "falko-mdm-subnet"
  ip_cidr_range            = "10.0.0.0/24"
  region                   = var.gcp_region
  network                  = google_compute_network.vpc_network.id
  private_ip_google_access = true
}

# 3. Cloud NAT Router
resource "google_compute_router" "router" {
  project = var.gcp_project_id
  name    = "falko-mdm-router"
  region  = var.gcp_region
  network = google_compute_network.vpc_network.id
}

# 4. Cloud NAT suojaamaan ulospäin suuntautuvaa liikennettä (esim. kiinteä reititys Applen APNs-palveluun)
resource "google_compute_router_nat" "nat" {
  project                            = var.gcp_project_id
  name                               = "falko-mdm-nat"
  region                             = var.gcp_region
  router                             = google_compute_router.router.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# 5. Serverless VPC Access Connector Cloud Run -integraatiota varten
resource "google_vpc_access_connector" "connector" {
  project       = var.gcp_project_id
  name          = "falko-mdm-connector"
  region        = var.gcp_region
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc_network.id
}
