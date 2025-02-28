#include "db/ProxyEntity.hpp"
#include "fmt/includes.h"

namespace NekoGui_fmt {
    void V2rayStreamSettings::BuildStreamSettingsSingBox(QJsonObject *outbound) {
        // https://sing-box.sagernet.org/configuration/shared/v2ray-transport

        if (network != "tcp") {
            QJsonObject transport{{"type", network}};
            if (network == "ws") {
                if (!host.isEmpty()) transport["headers"] = QJsonObject{{"Host", host}};
                // ws path & ed
                auto pathWithoutEd = SubStrBefore(path, "?ed=");
                if (!pathWithoutEd.isEmpty()) transport["path"] = pathWithoutEd;
                if (pathWithoutEd != path) {
                    auto ed = SubStrAfter(path, "?ed=").toInt();
                    if (ed > 0) {
                        transport["max_early_data"] = ed;
                        transport["early_data_header_name"] = "Sec-WebSocket-Protocol";
                    }
                }
                if (ws_early_data_length > 0) {
                    transport["max_early_data"] = ws_early_data_length;
                    transport["early_data_header_name"] = ws_early_data_name;
                }
            } else if (network == "http") {
                if (!path.isEmpty()) transport["path"] = path;
                if (!host.isEmpty()) transport["host"] = QList2QJsonArray(host.split(","));
            } else if (network == "grpc") {
                if (!path.isEmpty()) transport["service_name"] = path;
            } else if (network == "httpupgrade") {
                if (!path.isEmpty()) transport["path"] = path;
                if (!host.isEmpty()) transport["host"] = host;
            }
            outbound->insert("transport", transport);
        } else if (header_type == "http") {
            // TCP + headerType
            QJsonObject transport{
                {"type", "http"},
                {"method", "GET"},
                {"path", path},
                {"headers", QJsonObject{{"Host", QList2QJsonArray(host.split(","))}}},
            };
            outbound->insert("transport", transport);
        }

        // 对应字段 tls
        if (security == "tls") {
            QJsonObject tls{{"enabled", true}};
            if (allow_insecure || NekoGui::dataStore->skip_cert) tls["insecure"] = true;
            if (!sni.trimmed().isEmpty()) tls["server_name"] = sni;
            if (!certificate.trimmed().isEmpty()) {
                tls["certificate"] = certificate.trimmed();
            }
            if (!alpn.trimmed().isEmpty()) {
                tls["alpn"] = QList2QJsonArray(alpn.split(","));
            }
            QString fp = utlsFingerprint;
            if (!reality_pbk.trimmed().isEmpty()) {
                tls["reality"] = QJsonObject{
                    {"enabled", true},
                    {"public_key", reality_pbk},
                    {"short_id", reality_sid.split(",")[0]},
                };
                if (fp.isEmpty()) fp = "random";
            }
            if (!fp.isEmpty()) {
                tls["utls"] = QJsonObject{
                    {"enabled", true},
                    {"fingerprint", fp},
                };
            }
            outbound->insert("tls", tls);
        }

        if (outbound->value("type").toString() == "vmess" || outbound->value("type").toString() == "vless") {
            outbound->insert("packet_encoding", packet_encoding);
        }
    }

    CoreObjOutboundBuildResult SocksHttpBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        QJsonObject outbound;
        outbound["type"] = socks_http_type == type_HTTP ? "http" : "socks";
        if (socks_http_type == type_Socks4) outbound["version"] = "4";
        outbound["server"] = serverAddress;
        outbound["server_port"] = serverPort;

        if (!username.isEmpty() && !password.isEmpty()) {
            outbound["username"] = username;
            outbound["password"] = password;
        }

        stream->BuildStreamSettingsSingBox(&outbound);
        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult ShadowSocksBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        QJsonObject outbound{
            {"type", "shadowsocks"},
            {"server", serverAddress},
            {"server_port", serverPort},
            {"method", method},
            {"password", password}
        };

        if (uot != 0) {
            QJsonObject udp_over_tcp{
                {"enabled", true},
                {"version", uot},
            };
            outbound["udp_over_tcp"] = udp_over_tcp;
        } else {
            outbound["udp_over_tcp"] = false;
        }

        if (!plugin.trimmed().isEmpty()) {
            outbound["plugin"] = SubStrBefore(plugin, ";");
            outbound["plugin_opts"] = SubStrAfter(plugin, ";");
        }

        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult ShadowSocksRBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        QJsonObject outbound{
            {"type", "shadowsocksr"},
            {"server", serverAddress},
            {"server_port", serverPort},
            {"method", method},
            {"password", password},
            {"obfs",obfs},
            {"obfs_param",obfsParam},
            {"protocol",protocol},
            {"protocol_param",protocolParam}
        };

        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult VMessBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        QJsonObject outbound{
            {"type", "vmess"},
            {"server", serverAddress},
            {"server_port", serverPort},
            {"uuid", uuid.trimmed()},
            {"alter_id", aid},
            {"security", security},
        };

        stream->BuildStreamSettingsSingBox(&outbound);
        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult TrojanVLESSBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        QJsonObject outbound{
            {"type", proxy_type == proxy_VLESS ? "vless" : "trojan"},
            {"server", serverAddress},
            {"server_port", serverPort},
        };

        QJsonObject settings;
        if (proxy_type == proxy_VLESS) {
            if (flow.right(7) == "-udp443") {
                // 检查末尾是否包含"-udp443"，如果是，则删去
                flow.chop(7);
            } else if (flow == "none") {
                // 不使用 flow
                flow = "";
            }
            outbound["uuid"] = password.trimmed();
            outbound["flow"] = flow;
        } else {
            outbound["password"] = password;
        }

        stream->BuildStreamSettingsSingBox(&outbound);
        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult QUICBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        QJsonObject coreTlsObj{
            {"enabled", true},
            {"disable_sni", disableSni},
            {"insecure", allowInsecure},
            {"certificate", caText.trimmed()},
            {"server_name", sni},
        };
        if (!alpn.trimmed().isEmpty()) coreTlsObj["alpn"] = QList2QJsonArray(alpn.split(","));
        if (proxy_type == proxy_Hysteria2) coreTlsObj["alpn"] = "h3";

        QJsonObject outbound{
            {"server", serverAddress},
            {"server_port", serverPort},
            {"tls", coreTlsObj},
        };

        if (proxy_type == proxy_Hysteria) {
            outbound["type"] = "hysteria";
            outbound["obfs"] = obfsPassword;
            outbound["disable_mtu_discovery"] = disableMtuDiscovery;
            outbound["recv_window"] = streamReceiveWindow;
            outbound["recv_window_conn"] = connectionReceiveWindow;
            outbound["up_mbps"] = uploadMbps;
            outbound["down_mbps"] = downloadMbps;

            if (authPayloadType == hysteria_auth_base64) outbound["auth"] = authPayload;
            if (authPayloadType == hysteria_auth_string) outbound["auth_str"] = authPayload;
        } else if (proxy_type == proxy_Hysteria2) {
            outbound["type"] = "hysteria2";
            outbound["password"] = password;
            outbound["up_mbps"] = uploadMbps;
            outbound["down_mbps"] = downloadMbps;

            if (!obfsPassword.isEmpty()) {
                outbound["obfs"] = QJsonObject{
                    {"type", "salamander"},
                    {"password", obfsPassword},
                };
            }

            if (!hopPort.isEmpty()){
                outbound["server_ports"] = QJsonArray::fromStringList(QString(hopPort).replace('-', ':').split(',', Qt::SkipEmptyParts));
                outbound["hop_interval"] = QString::number(hopInterval) + "s";
            }
        } else if (proxy_type == proxy_TUIC) {
            outbound["type"] = "tuic";
            outbound["uuid"] = uuid;
            outbound["password"] = password;
            outbound["congestion_control"] = congestionControl;
            if (uos) {
                outbound["udp_over_stream"] = true;
            } else {
                outbound["udp_relay_mode"] = udpRelayMode;
            }
            outbound["zero_rtt_handshake"] = zeroRttHandshake;
            if (!heartbeat.trimmed().isEmpty()) outbound["heartbeat"] = heartbeat;
        }

        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult SSHBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        QJsonObject outbound{
            {"type", "ssh"},
            {"server", serverAddress},
            {"server_port", serverPort},
            {"user", user},
            {"password", password},
            {"private_key", privateKey},
            {"private_key_path", privateKeyPath},
            {"private_key_passphrase", privateKeyPassphrase},
            {"host_key", QString2QJsonArray(hostKey)},
            {"host_key_algorithms", QString2QJsonArray(hostKeyAlgorithms)},
            {"client_version", clientVersion}
        };

        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult WireGuardBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        auto tun_name = "nekoray-wg";
#ifdef Q_OS_MACOS
        tun_name = "uwg9";
#endif

        QJsonObject outbound{
            {"type", "wireguard"},
            {"server", serverAddress},
            {"server_port", serverPort},
            {"interface_name", tun_name},
            {"private_key", privateKey},
            {"peer_public_key", publicKey},
            {"pre_shared_key", preSharedKey},
            {"local_address", QString2QJsonArray(localAddress)},
            {"reserved", QString2QJsonArray(reserved)},
            {"mtu", MTU},
            {"gso", enableGSO},
            {"system_interface", useSystemInterface}
        };

        result.outbound = outbound;
        return result;
    }

    CoreObjOutboundBuildResult CustomBean::BuildCoreObjSingBox() {
        CoreObjOutboundBuildResult result;

        if (core == "internal") {
            result.outbound = QString2QJsonObject(config_simple);
        }

        return result;
    }
} // namespace NekoGui_fmt
