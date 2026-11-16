import random
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class CloudConfig:
    accounts_aws: Tuple[str, ...] = ("123456789012",)
    subscriptions_azure: Tuple[str, ...] = ("00000000-0000-0000-0000-000000000000",)
    projects_gcp: Tuple[str, ...] = ("acme-prod",)
    regions_aws: Tuple[str, ...] = ("us-east-1", "us-west-2", "eu-west-1")
    regions_azure: Tuple[str, ...] = ("eastus", "westeurope")
    regions_gcp: Tuple[str, ...] = ("us-central1", "europe-west1")
    instance_counts: Dict[str, int] = None  # provider -> count
    container_counts: Dict[str, int] = None  # provider -> count

    def __post_init__(self) -> None:
        if self.instance_counts is None:
            self.instance_counts = {"aws": 30, "azure": 20, "gcp": 20}
        if self.container_counts is None:
            self.container_counts = {"aws": 50, "azure": 35, "gcp": 35}


_IAM_PERMISSIONS_BY_ROLE = {
    # AWS roles
    "ec2-web": [
        "ec2:Describe*", "elasticloadbalancing:*", "s3:GetObject",
        "logs:PutLogEvents", "cloudwatch:PutMetricData", "secretsmanager:GetSecretValue",
    ],
    "ec2-batch": [
        "s3:*", "athena:*", "dynamodb:*", "logs:PutLogEvents",
        "sts:AssumeRole", "secretsmanager:GetSecretValue", "sagemaker:*",
    ],
    "ec2-app": [
        "lambda:InvokeFunction", "sqs:*", "dynamodb:*", "s3:GetObject",
        "logs:PutLogEvents", "secretsmanager:GetSecretValue",
    ],
    # Azure service principals (mapped by app tag)
    "azure-web": [
        "Microsoft.Compute/virtualMachines/read", "Microsoft.Network/loadBalancers/*",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.OperationalInsights/workspaces/write", "Microsoft.KeyVault/vaults/secrets/read",
    ],
    "azure-etl": [
        "Microsoft.Storage/storageAccounts/*", "Microsoft.Sql/servers/*",
        "Microsoft.DataFactory/factories/*", "Microsoft.OperationalInsights/workspaces/write",
        "Microsoft.KeyVault/vaults/secrets/read",
    ],
    "azure-billing": [
        "Microsoft.ServiceBus/namespaces/*", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.Sql/servers/*", "Microsoft.Web/sites/*",
        "Microsoft.OperationalInsights/workspaces/write", "Microsoft.KeyVault/vaults/secrets/read",
    ],
    "azure-ml": [
        "Microsoft.MachineLearningServices/workspaces/*",
        "Microsoft.Storage/storageAccounts/*", "Microsoft.Compute/virtualMachines/*",
        "Microsoft.OperationalInsights/workspaces/write", "Microsoft.KeyVault/vaults/secrets/read",
    ],
    # GCP roles
    "compute-default": [
        "storage.objects.get", "storage.objects.list", "logging.logEntries.create",
        "monitoring.timeSeries.create", "secretmanager.versions.access",
    ],
    "app-runner": [
        "cloudfunctions.functions.invoke", "pubsub.*", "datastore.*",
        "storage.objects.get", "logging.logEntries.create", "secretmanager.versions.access",
    ],
}


def _resolve_permissions(provider: str, iam_role: str, app_tag: str) -> List[str]:
    """Resolve permissions list based on provider, IAM role, and app tag."""
    # Try direct role match first
    perms = _IAM_PERMISSIONS_BY_ROLE.get(iam_role)
    if perms:
        return list(perms)
    # Try provider-app composite key
    composite = f"{provider}-{app_tag}"
    perms = _IAM_PERMISSIONS_BY_ROLE.get(composite)
    if perms:
        return list(perms)
    # Fallback
    if provider == "aws":
        return ["s3:GetObject", "logs:PutLogEvents"]
    if provider == "azure":
        return ["Microsoft.Storage/storageAccounts/read", "Microsoft.OperationalInsights/workspaces/write"]
    return ["storage.objects.get", "logging.logEntries.create"]


def _pick_image(provider: str, rng: random.Random) -> str:
    if provider == "aws":
        return rng.choice(["ami-ubuntu-22.04", "ami-windows-2022", "ami-amazonlinux-2"])
    if provider == "azure":
        return rng.choice(["UbuntuLTS-22.04", "Windows-2022", "Debian-12"])
    return rng.choice(["ubuntu-2204-lts", "windows-2022", "cos-109"])


def _instance_type(provider: str, rng: random.Random) -> str:
    if provider == "aws":
        return rng.choice(["t3.medium", "t3.large", "m6i.large", "c6g.large"])
    if provider == "azure":
        return rng.choice(["Standard_B2s", "Standard_D4s_v5", "Standard_D8s_v5"])
    return rng.choice(["e2-standard-2", "n2-standard-4", "c2d-standard-4"])


def _private_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _public_ip(rng: random.Random) -> str:
    return f"203.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def generate_cloud_instances(cfg: CloudConfig, rng: random.Random) -> List[Dict]:
    instances: List[Dict] = []
    # AWS
    for i in range(cfg.instance_counts.get("aws", 0)):
        region = rng.choice(cfg.regions_aws)
        acc = rng.choice(cfg.accounts_aws)
        app_tag = rng.choice(["billing", "web", "etl", "ml"])
        iam_role = rng.choice(["ec2-app", "ec2-batch", "ec2-web"])
        instances.append({
            "provider": "aws",
            "instanceId": f"i-{rng.randint(10**11, 10**12-1):012d}",
            "accountId": acc,
            "region": region,
            "image": _pick_image("aws", rng),
            "instanceType": _instance_type("aws", rng),
            "tags": {"env": rng.choice(["prod", "stage", "dev"]), "app": app_tag},
            "network": {
                "vpc": f"vpc-{rng.randint(1000, 9999)}",
                "subnet": f"subnet-{rng.randint(1000, 9999)}",
                "privateIp": _private_ip(rng),
                "publicIp": _public_ip(rng),
                "securityGroups": [f"sg-{rng.randint(10000, 99999)}"],
            },
            "iam": {"role": iam_role, "permissions": _resolve_permissions("aws", iam_role, app_tag)},
        })
    # Azure
    for i in range(cfg.instance_counts.get("azure", 0)):
        region = rng.choice(cfg.regions_azure)
        sub = rng.choice(cfg.subscriptions_azure)
        app_tag = rng.choice(["billing", "web", "etl", "ml"])
        spn = f"spn-{rng.randint(100000, 999999)}"
        instances.append({
            "provider": "azure",
            "instanceId": f"vm-{rng.randint(10**6, 10**7-1)}",
            "subscriptionId": sub,
            "region": region,
            "image": _pick_image("azure", rng),
            "instanceType": _instance_type("azure", rng),
            "tags": {"env": rng.choice(["prod", "stage", "dev"]), "app": app_tag},
            "network": {
                "vnet": f"vnet-{rng.randint(1000, 9999)}",
                "subnet": f"subnet-{rng.randint(1000, 9999)}",
                "privateIp": _private_ip(rng),
                "publicIp": _public_ip(rng),
                "securityGroups": [f"nsg-{rng.randint(10000, 99999)}"],
            },
            "iam": {"servicePrincipal": spn, "permissions": _resolve_permissions("azure", spn, app_tag)},
        })
    # GCP
    for i in range(cfg.instance_counts.get("gcp", 0)):
        region = rng.choice(cfg.regions_gcp)
        proj = rng.choice(cfg.projects_gcp)
        app_tag = rng.choice(["billing", "web", "etl", "ml"])
        iam_role = rng.choice(["compute-default", "app-runner"])
        instances.append({
            "provider": "gcp",
            "instanceId": f"gce-{rng.randint(10**6, 10**7-1)}",
            "projectId": proj,
            "region": region,
            "zone": f"{region}-a",
            "image": _pick_image("gcp", rng),
            "instanceType": _instance_type("gcp", rng),
            "tags": {"env": rng.choice(["prod", "stage", "dev"]), "app": app_tag},
            "network": {
                "subnet": f"subnet-{rng.randint(1000, 9999)}",
                "privateIp": _private_ip(rng),
                "publicIp": _public_ip(rng),
                "securityGroups": [f"fw-{rng.randint(10000, 99999)}"],
            },
            "iam": {"role": iam_role, "permissions": _resolve_permissions("gcp", iam_role, app_tag)},
        })
    return instances


def generate_containers(cfg: CloudConfig, instances: List[Dict], rng: random.Random) -> List[Dict]:
    containers: List[Dict] = []
    def pick_instance(provider: str) -> Dict:
        candidates = [i for i in instances if i["provider"] == provider]
        return rng.choice(candidates) if candidates else rng.choice(instances)

    # Simple distribution per provider
    for provider in ("aws", "azure", "gcp"):
        for _ in range(cfg.container_counts.get(provider, 0)):
            inst = pick_instance(provider)
            containers.append({
                "id": f"ctr-{rng.randint(10**7, 10**8-1)}",
                "provider": provider,
                "cluster": f"{provider}-eks-aks-gke-{rng.randint(100,999)}",
                "node": inst.get("instanceId"),
                "namespace": rng.choice(["default", "prod", "stage", "dev"]),
                "pod": f"{rng.choice(['web','api','batch','worker'])}-{rng.randint(1000,9999)}",
                "container": rng.choice(["app", "sidecar", "init"]),
                "image": rng.choice([
                    "ghcr.io/acme/web:1.4.2",
                    "ghcr.io/acme/api:2.1.0",
                    "gcr.io/acme/etl:0.9.3",
                    "mcr.microsoft.com/oss/nginx/nginx:1.25",
                ]),
                "labels": {"app": rng.choice(["web", "api", "etl", "ml"])},
            })
    return containers


