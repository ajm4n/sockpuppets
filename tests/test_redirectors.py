import pytest
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redirectors import RedirectorConfig, load_redirector, list_redirectors, generate_deploy_config


def test_load_default_redirector():
    config = load_redirector("default")
    assert config.name == "default"
    assert config.type == "direct"


def test_load_missing_redirector_raises():
    with pytest.raises(FileNotFoundError):
        load_redirector("nonexistent_xyz_123")


def test_list_redirectors_includes_default():
    configs = list_redirectors()
    names = [c.name for c in configs]
    assert "default" in names


def test_generate_nginx_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
        trusted=True,
        profile="cdn-cloudfront",
        allow_user_agents=["Mozilla/5.0*"],
        decoy="redirect",
        decoy_target="https://www.example.com",
    )
    output = generate_deploy_config(config, "nginx")
    assert "proxy_pass" in output
    assert "10.0.0.5:8443" in output
    assert "cdn.example.com" in output


def test_generate_apache_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
        trusted=True,
        profile="cdn-cloudfront",
        allow_user_agents=["Mozilla/5.0*"],
        decoy="redirect",
        decoy_target="https://www.example.com",
    )
    output = generate_deploy_config(config, "apache")
    assert "RewriteEngine" in output
    assert "10.0.0.5:8443" in output


def test_generate_socat_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
    )
    output = generate_deploy_config(config, "socat")
    assert "socat" in output
    assert "10.0.0.5" in output


def test_generate_iptables_config():
    config = RedirectorConfig(
        name="test-redir",
        type="https",
        listen="0.0.0.0:443",
        backend="10.0.0.5:8443",
        domain="cdn.example.com",
    )
    output = generate_deploy_config(config, "iptables")
    assert "iptables" in output
    assert "DNAT" in output


def test_generate_lambda_config():
    config = RedirectorConfig(
        name="test-redir",
        type="cloud-function",
        listen="",
        backend="10.0.0.5:8443",
        domain="api.example.com",
    )
    output = generate_deploy_config(config, "lambda")
    assert "lambda_handler" in output
    assert "10.0.0.5:8443" in output


def test_generate_unknown_format_raises():
    config = RedirectorConfig(name="test", type="https", backend="1.2.3.4:443", domain="x.com")
    with pytest.raises(ValueError):
        generate_deploy_config(config, "unknown_format")
