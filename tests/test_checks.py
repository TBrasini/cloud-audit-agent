"""
Tests des contrôles de sécurité contre une fausse infra AWS (moto).
"""
import boto3
from moto import mock_aws

from scanner.checks import (
    check_ebs_unencrypted_volumes,
    check_root_account_mfa,
    check_s3_public_buckets,
    check_security_groups_open_ingress,
)


@mock_aws
def test_check_s3_public_buckets_flags_bucket_without_block():
    s3 = boto3.client("s3", region_name="eu-west-3")
    s3.create_bucket(
        Bucket="test-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-west-3"},
    )
    findings = check_s3_public_buckets(s3)
    assert any(f["check_id"] == "S3-01" for f in findings)


@mock_aws
def test_check_s3_public_buckets_ignores_protected_bucket():
    s3 = boto3.client("s3", region_name="eu-west-3")
    s3.create_bucket(
        Bucket="protected-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-west-3"},
    )
    s3.put_public_access_block(
        Bucket="protected-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    findings = check_s3_public_buckets(s3)
    assert not any(f["resource"] == "s3://protected-bucket" for f in findings)


@mock_aws
def test_check_security_groups_open_ssh():
    ec2 = boto3.client("ec2", region_name="eu-west-3")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="open-ssh", Description="test", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    findings = check_security_groups_open_ingress(ec2)
    assert any(f["check_id"] == "SG-01" for f in findings)


@mock_aws
def test_check_ebs_unencrypted_volume_flagged():
    ec2 = boto3.client("ec2", region_name="eu-west-3")
    ec2.create_volume(AvailabilityZone="eu-west-3a", Size=1, Encrypted=False)
    findings = check_ebs_unencrypted_volumes(ec2)
    assert any(f["check_id"] == "EBS-01" for f in findings)


@mock_aws
def test_check_root_account_mfa_no_mfa_by_default():
    iam = boto3.client("iam", region_name="eu-west-3")
    findings = check_root_account_mfa(iam)
    assert any(f["check_id"] == "ROOT-01" for f in findings)
