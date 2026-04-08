# `sto`

Strato: AWS Auditor

**Usage**:

```console
$ sto [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.

**Commands**:

* `s3`: S3 Auditing &amp; Inventory
* `ec2`: EC2 Auditing &amp; Inventory
* `lambda`: Lambda Auditing &amp; Inventory
* `rds`: RDS Auditing &amp; Inventory
* `ebs`: EBS Auditing &amp; Inventory
* `ecs`: EC2 Auditing &amp; Inventory

## `sto s3`

S3 Auditing &amp; Inventory

**Usage**:

```console
$ sto s3 [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: S3 Inventory &amp; Cost Analysis

### `sto s3 inventory`

S3 Inventory &amp; Cost Analysis

**Usage**:

```console
$ sto s3 inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run all scan.
* `scan`: Gather an inventory of S3 Buckets

#### `sto s3 inventory all`

Run all scan.

**Usage**:

```console
$ sto s3 inventory all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 inventory scan`

Gather an inventory of S3 Buckets

**Usage**:

```console
$ sto s3 inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

## `sto ec2`

EC2 Auditing &amp; Inventory

**Usage**:

```console
$ sto ec2 [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: EC2 Inventory &amp; Audit
* `reserved`: EC2 Reserved Instances

### `sto ec2 inventory`

EC2 Inventory &amp; Audit

**Usage**:

```console
$ sto ec2 inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run all scan.
* `scan`: Gather a comprehensive inventory of EC2...

#### `sto ec2 inventory all`

Run all scan.

**Usage**:

```console
$ sto ec2 inventory all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto ec2 inventory scan`

Gather a comprehensive inventory of EC2 Instances

**Usage**:

```console
$ sto ec2 inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

### `sto ec2 reserved`

EC2 Reserved Instances

**Usage**:

```console
$ sto ec2 reserved [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `scan`: Inventory of EC2 Reserved Instances

#### `sto ec2 reserved scan`

Inventory of EC2 Reserved Instances

**Usage**:

```console
$ sto ec2 reserved scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

## `sto lambda`

Lambda Auditing &amp; Inventory

**Usage**:

```console
$ sto lambda [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: Lambda Inventory &amp; Audit

### `sto lambda inventory`

Lambda Inventory &amp; Audit

**Usage**:

```console
$ sto lambda inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `scan`: Gather a inventory of Lambda Functions

#### `sto lambda inventory scan`

Gather a inventory of Lambda Functions

**Usage**:

```console
$ sto lambda inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

## `sto rds`

RDS Auditing &amp; Inventory

**Usage**:

```console
$ sto rds [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: RDS Inventory
* `reserved`: RDS Reserved Instance Contracts

### `sto rds inventory`

RDS Inventory

**Usage**:

```console
$ sto rds inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run all scan.
* `scan`: Gather inventory of RDS Instances

#### `sto rds inventory all`

Run all scan.

**Usage**:

```console
$ sto rds inventory all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan (e.g. us-east-1)
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto rds inventory scan`

Gather inventory of RDS Instances

**Usage**:

```console
$ sto rds inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan (e.g. us-east-1)
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

### `sto rds reserved`

RDS Reserved Instance Contracts

**Usage**:

```console
$ sto rds reserved [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `scan`: Scan for Purchased Reserved Instances...

#### `sto rds reserved scan`

Scan for Purchased Reserved Instances (Active Contracts).

**Usage**:

```console
$ sto rds reserved scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

## `sto ebs`

EBS Auditing &amp; Inventory

**Usage**:

```console
$ sto ebs [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: EBS Volume Inventory

### `sto ebs inventory`

EBS Volume Inventory

**Usage**:

```console
$ sto ebs inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `scan`

#### `sto ebs inventory scan`

**Usage**:

```console
$ sto ebs inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`
* `--csv`
* `--region TEXT`
* `--org-role TEXT`
* `--help`: Show this message and exit.

## `sto ecs`

EC2 Auditing &amp; Inventory

**Usage**:

```console
$ sto ecs [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: ECS Inventory

### `sto ecs inventory`

ECS Inventory

**Usage**:

```console
$ sto ecs inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run all scan.
* `scan`: Gather inventory of ECS Clusters and Services

#### `sto ecs inventory all`

Run all scan.

**Usage**:

```console
$ sto ecs inventory all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto ecs inventory scan`

Gather inventory of ECS Clusters and Services

**Usage**:

```console
$ sto ecs inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.
