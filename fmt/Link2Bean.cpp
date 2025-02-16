#include "db/ProxyEntity.hpp"
#include "fmt/includes.h"

#include <QUrlQuery>

namespace NekoGui_fmt {
    bool SocksHttpBean::TryParseLink(const QString &link) {
        auto url = QUrl(link);
        if (!url.isValid()) return false;
        auto query = GetQuery(url);

        if (link.startsWith("socks4")) socks_http_type = type_Socks4;
        if (link.startsWith("http")) socks_http_type = type_HTTP;
        name = url.fragment(QUrl::FullyDecoded);
        serverAddress = url.host();
        serverPort = url.port();
        username = url.userName();
        password = url.password();
        if (serverPort == -1) serverPort = socks_http_type == type_HTTP ? 443 : 1080;

        // v2rayN fmt
        if (password.isEmpty() && !username.isEmpty()) {
            QString n = DecodeB64IfValid(username);
            if (!n.isEmpty()) {
                username = SubStrBefore(n, ":");
                password = SubStrAfter(n, ":");
            }
        }

        stream->security = GetQueryValue(query, "security", "");
        stream->sni = GetQueryValue(query, "sni");
        if (link.startsWith("https")) stream->security = "tls";

        return !serverAddress.isEmpty();
    }

    bool ShadowSocksBean::TryParseLink(const QString &link) {
        QUrl url;
        if (SubStrBefore(link, "#").contains("@")) {
            url = QUrl(link);
        } else if (SubStrBefore(link, "#").contains("?")) {
            url = QUrl("ss://" + DecodeBase64OrBase64Url(SubStrBefore(SubStrAfter(link, "://"), "?")) + "?" + SubStrAfter(link, "?"));
        } else if (link.contains("#")) {
            url = QUrl("ss://" + DecodeBase64OrBase64Url(SubStrBefore(SubStrAfter(link, "://"), "#")) + "#" + SubStrAfter(link, "#"));
        } else {
            url = QUrl("ss://" + DecodeBase64OrBase64Url(SubStrAfter(link, "://")));
        }
        if (!url.isValid()) return false;

        name = url.fragment(QUrl::FullyDecoded);
        serverAddress = url.host();
        serverPort = url.port();

        if (url.password().isEmpty()) {
            // traditional format
            auto method_password = DecodeBase64OrBase64Url(url.userName());
            if (method_password.isEmpty()) return false;
            method = SubStrBefore(method_password, ":");
            password = SubStrAfter(method_password, ":");
        } else {
            // 2022 format
            method = url.userName();
            password = url.password();
        }

        auto query = GetQuery(url);
        if (!query.queryItemValue("plugin").startsWith("none")) {
            plugin = query.queryItemValue("plugin").replace("simple-obfs;", "obfs-local;");
        }
        auto mux_str = GetQueryValue(query, "mux", "");
        if (mux_str == "true") {
            mux_state = 1;
        } else if (mux_str == "false") {
            mux_state = 2;
        }

        // *ray misnomer
        if (method == "chacha20-poly1305")
            method = "chacha20-ietf-poly1305";
        else if (method == "xchacha20-poly1305")
            method = "xchacha20-ietf-poly1305";

        return !(serverAddress.isEmpty() || method.isEmpty() || password.isEmpty());
    }

    bool ShadowSocksRBean::TryParseLink(const QString &link) {
        QString decodedData = DecodeBase64OrBase64Url(SubStrAfter(link, "://"));
        QStringList parts = decodedData.split(':');
        if (parts.size() < 6)
            return false;

        serverAddress = parts[0];
        serverPort = parts[1].toInt();
        protocol = parts[2];
        method = parts[3];
        obfs = parts[4];
        password = DecodeBase64OrBase64Url(parts[5].split("/")[0]);

        auto query = GetQuery(QUrl("ssr://" + decodedData));
        obfsParam = DecodeBase64OrBase64Url(query.queryItemValue("obfsparam"));
        protocolParam = DecodeBase64OrBase64Url(query.queryItemValue("protoparam"));
        name = DecodeBase64OrBase64Url(query.queryItemValue("remarks"));

        return !serverAddress.isEmpty();
    }

    bool VMessBean::TryParseLink(const QString &link) {
        if (!link.contains("?")) {
            // V2RayN Format
            auto objN = QString2QJsonObject(DecodeBase64OrBase64Url(SubStrAfter(link, "://")));
            if (objN.isEmpty()) return false;
            // REQUIRED
            uuid = objN["id"].toString();
            serverAddress = objN["add"].toString();
            serverPort = objN["port"].toVariant().toInt();
            // OPTIONAL
            name = objN["ps"].toString();
            aid = objN["aid"].toVariant().toInt();
            stream->host = objN["host"].toString();
            stream->path = objN["path"].toString();
            stream->sni = objN["sni"].toString();
            stream->header_type = objN["type"].toString();
            auto net = objN["net"].toString();
            if (!net.isEmpty()) {
                if (net == "h2") net = "http";
                stream->network = net;
            }
            auto scy = objN["scy"].toString();
            if (!scy.isEmpty()) security = scy;
            // TLS (XTLS?)
            stream->security = objN["tls"].toString();
            // TODO quic & kcp
        } else {
            auto url = SubStrBefore(link, "?").contains("@")
                           ? QUrl(link)
                           : QUrl("vmess://" + DecodeBase64OrBase64Url(SubStrBefore(SubStrAfter(link, "://"), "?")) + "?" + SubStrAfter(link, "?"));
            if (!url.isValid()) return false;
            auto query = GetQuery(url);

            if (!url.password().isEmpty()) {
                name = query.queryItemValue("remarks");
                uuid = url.password();
                security = url.userName();
                stream->network = GetQueryValue(query, "obfs", "tcp").replace("websocket", "ws");
                if (GetQueryValue(query, "tls") == "1") stream->security = "tls";
            } else {
                // https://github.com/XTLS/Xray-core/discussions/716
                name = url.fragment(QUrl::FullyDecoded);
                uuid = url.userName();
                security = GetQueryValue(query, "encryption", "auto");
                stream->network = GetQueryValue(query, "type", "tcp").replace("h2", "http");
                stream->security = GetQueryValue(query, "security", "").replace("reality", "tls");
            }
            serverAddress = url.host();
            serverPort = url.port();
            if (serverPort == -1) serverPort = 443;
            aid = GetQueryValue(query, "alterId", "0").toInt();

            // security
            auto sni1 = GetQueryValue(query, "sni");
            auto sni2 = GetQueryValue(query, "peer");
            if (!sni1.isEmpty()) stream->sni = sni1;
            if (!sni2.isEmpty()) stream->sni = sni2;
            if (!query.queryItemValue("allowInsecure").isEmpty()) stream->allow_insecure = true;
            stream->reality_pbk = GetQueryValue(query, "pbk", "");
            stream->reality_sid = GetQueryValue(query, "sid", "");
            stream->reality_spx = GetQueryValue(query, "spx", "");
            stream->utlsFingerprint = GetQueryValue(query, "fp", "");
            if (stream->utlsFingerprint.isEmpty()) {
                stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
            }

            // mux
            auto mux_str = GetQueryValue(query, "mux", "");
            if (mux_str == "true") {
                mux_state = 1;
            } else if (mux_str == "false") {
                mux_state = 2;
            }

            // type
            if (stream->network == "tcp") {
                if (GetQueryValue(query, "headerType") == "http") {
                    stream->header_type = "http";
                    stream->path = GetQueryValue(query, "path", "");
                    stream->host = GetQueryValue(query, "host", "");
                }
            } else if (stream->network == "http") {
                stream->path = GetQueryValue(query, "path", "");
                stream->host = GetQueryValue(query, "host", "").replace("|", ",");
            } else if (stream->network == "httpupgrade") {
                stream->path = GetQueryValue(query, "path", "");
                stream->host = GetQueryValue(query, "host", "");
            } else if (stream->network == "ws") {
                stream->path = GetQueryValue(query, "path", "");
                stream->host = GetQueryValue(query, "host", "");
            } else if (stream->network == "grpc") {
                stream->path = !GetQueryValue(query, "serviceName").isEmpty() ? GetQueryValue(query, "serviceName") : GetQueryValue(query, "path");
            }
        }
        return !(uuid.isEmpty() || serverAddress.isEmpty());
    }

    bool TrojanVLESSBean::TryParseLink(const QString &link) {
        auto url = SubStrBefore(link, "?").contains("@")
                       ? QUrl(link)
                       : QUrl("url://" + DecodeBase64OrBase64Url(SubStrBefore(SubStrAfter(link, "://"), "?")) + "?" + SubStrAfter(link, "?"));
        if (!url.isValid()) return false;
        auto query = GetQuery(url);

        if (!url.password().isEmpty()) {
            name = query.queryItemValue("remarks");
            password = url.password();
            stream->network = GetQueryValue(query, "obfs", "tcp").replace("websocket", "ws");
            if (GetQueryValue(query, "tls") == "1") stream->security = "tls";
        } else {
            name = url.fragment(QUrl::FullyDecoded);
            password = url.userName();
            stream->network = GetQueryValue(query, "type", "tcp").replace("h2", "http");
            if (proxy_type == proxy_Trojan) {
                stream->security = GetQueryValue(query, "security", "tls").replace("reality", "tls").replace("none", "");
            } else {
                stream->security = GetQueryValue(query, "security", "").replace("reality", "tls").replace("none", "");
            }
        }
        serverAddress = url.host();
        serverPort = url.port();
        if (serverPort == -1) serverPort = 443;

        // security
        auto sni1 = GetQueryValue(query, "sni");
        auto sni2 = GetQueryValue(query, "peer");
        if (!sni1.isEmpty()) stream->sni = sni1;
        if (!sni2.isEmpty()) stream->sni = sni2;
        stream->alpn = GetQueryValue(query, "alpn");
        if (!query.queryItemValue("allowInsecure").isEmpty() || (stream->security == "tls" && stream->sni.isEmpty()))
            stream->allow_insecure = true;
        stream->reality_pbk = GetQueryValue(query, "pbk", "");
        stream->reality_sid = GetQueryValue(query, "sid", "");
        stream->reality_spx = GetQueryValue(query, "spx", "");
        stream->utlsFingerprint = GetQueryValue(query, "fp", "");
        if (stream->utlsFingerprint.isEmpty()) {
            stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
        }

        // type
        if (stream->network == "ws") {
            stream->path = GetQueryValue(query, "path", "");
            stream->host = GetQueryValue(query, "host", "");
        } else if (stream->network == "http") {
            stream->path = GetQueryValue(query, "path", "");
            stream->host = GetQueryValue(query, "host", "").replace("|", ",");
        } else if (stream->network == "httpupgrade") {
            stream->path = GetQueryValue(query, "path", "");
            stream->host = GetQueryValue(query, "host", "");
        } else if (stream->network == "grpc") {
            stream->path = !GetQueryValue(query, "serviceName").isEmpty() ? GetQueryValue(query, "serviceName") : GetQueryValue(query, "path");
        } else if (stream->network == "tcp") {
            if (GetQueryValue(query, "headerType") == "http") {
                stream->header_type = "http";
                stream->path = GetQueryValue(query, "path", "");
                stream->host = GetQueryValue(query, "host", "");
            }
        }

        // mux
        auto mux_str = GetQueryValue(query, "mux", "");
        if (mux_str == "true") {
            mux_state = 1;
        } else if (mux_str == "false") {
            mux_state = 2;
        }

        // protocol
        if (proxy_type == proxy_VLESS) {
            if (GetQueryValue(query, "flow") == "xtls-rprx-vision" || GetQueryValue(query, "xtls") == "2")
                flow = "xtls-rprx-vision";
        }

        return !(password.isEmpty() || serverAddress.isEmpty());
    }

    bool NaiveBean::TryParseLink(const QString &link) {
        auto url = QUrl(link);
        if (!url.isValid()) return false;

        protocol = url.scheme().replace("naive+", "");
        if (protocol != "https" && protocol != "quic") return false;

        name = url.fragment(QUrl::FullyDecoded);
        serverAddress = url.host();
        serverPort = url.port();
        username = url.userName();
        password = url.password();

        return !(username.isEmpty() || password.isEmpty() || serverAddress.isEmpty());
    }

    bool QUICBean::TryParseLink(const QString &link) {
        auto url = QUrl(link);
        auto query = QUrlQuery(url.query());
        if (url.host().isEmpty() || url.port() == -1) return false;

        if (url.scheme() == "hysteria") {
            // https://hysteria.network/docs/uri-scheme/
            if (!query.hasQueryItem("upmbps") || !query.hasQueryItem("downmbps")) return false;

            name = url.fragment(QUrl::FullyDecoded);
            serverAddress = url.host();
            serverPort = url.port();
            obfsPassword = query.queryItemValue("obfsParam");
            allowInsecure = QStringList{"1", "true"}.contains(query.queryItemValue("insecure"));
            uploadMbps = query.queryItemValue("upmbps").toInt();
            downloadMbps = query.queryItemValue("downmbps").toInt();

            auto protocolStr = (query.hasQueryItem("protocol") ? query.queryItemValue("protocol") : "udp").toLower();
            if (protocolStr == "faketcp") {
                hyProtocol = NekoGui_fmt::QUICBean::hysteria_protocol_facktcp;
            } else if (protocolStr.startsWith("wechat")) {
                hyProtocol = NekoGui_fmt::QUICBean::hysteria_protocol_wechat_video;
            }

            if (query.hasQueryItem("auth")) {
                authPayload = query.queryItemValue("auth");
                authPayloadType = NekoGui_fmt::QUICBean::hysteria_auth_string;
            }

            alpn = query.queryItemValue("alpn");
            sni = FIRST_OR_SECOND(query.queryItemValue("peer"), query.queryItemValue("sni"));

            connectionReceiveWindow = query.queryItemValue("recv_window").toInt();
            streamReceiveWindow = query.queryItemValue("recv_window_conn").toInt();
        } else if (url.scheme() == "tuic") {
            // by daeuniverse
            // https://github.com/daeuniverse/dae/discussions/182

            name = url.fragment(QUrl::FullyDecoded);
            serverAddress = url.host();
            if (serverPort == -1) serverPort = 443;
            serverPort = url.port();

            uuid = url.userName();
            password = url.password();

            congestionControl = query.queryItemValue("congestion_control");
            alpn = query.queryItemValue("alpn");
            sni = query.queryItemValue("sni");
            udpRelayMode = query.queryItemValue("udp_relay_mode");
            allowInsecure = query.queryItemValue("allow_insecure") == "1";
            disableSni = query.queryItemValue("disable_sni") == "1";
        } else if (QStringList{"hy2", "hysteria2"}.contains(url.scheme())) {
            name = url.fragment(QUrl::FullyDecoded);
            serverAddress = url.host();
            serverPort = url.port();
            obfsPassword = query.queryItemValue("obfs-password");
            allowInsecure = QStringList{"1", "true"}.contains(query.queryItemValue("insecure"));

            if (url.password().isEmpty()) {
                password = url.userName();
            } else {
                password = url.userName() + ":" + url.password();
            }

            sni = query.queryItemValue("sni");
        }
        return !serverAddress.isEmpty();
    }

    bool SSHBean::TryParseLink(const QString &link) {
        auto url = QUrl(link);
        if (!url.isValid()) return false;
        auto query = GetQuery(url);

        name = url.fragment(QUrl::FullyDecoded);
        serverAddress = url.host();
        serverPort = url.port();
        user = query.queryItemValue("user");
        password = query.queryItemValue("password");
        privateKey = DecodeB64IfValid(query.queryItemValue("private_key"), QByteArray::Base64Option::Base64UrlEncoding);
        privateKeyPath = query.queryItemValue("private_key_path");
        privateKeyPassphrase = query.queryItemValue("private_key_passphrase");
        hostKey = query.queryItemValue("host_key");
        hostKeyAlgorithms = query.queryItemValue("host_key_algorithms");
        clientVersion = query.queryItemValue("client_version");

        return !serverAddress.isEmpty();
    }

    bool WireGuardBean::TryParseLink(const QString &link) {
        auto url = QUrl(link);
        if (!url.isValid()) return false;
        auto query = GetQuery(url);

        name = url.fragment(QUrl::FullyDecoded);
        serverAddress = url.host();
        serverPort = url.port();
        privateKey = query.queryItemValue("private_key");
        publicKey = query.queryItemValue("peer_public_key");
        preSharedKey = query.queryItemValue("pre_shared_key");
        localAddress = query.queryItemValue("local_address");
        reserved = query.queryItemValue("reserved");
        MTU = query.queryItemValue("mtu").toInt();
        useSystemInterface = query.queryItemValue("use_system_interface") == "true";

        return !serverAddress.isEmpty();
    }

} // namespace NekoGui_fmt