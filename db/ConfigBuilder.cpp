#include "db/ConfigBuilder.hpp"
#include "db/Database.hpp"
#include "fmt/includes.h"
#include "fmt/Preset.hpp"

#include <QApplication>
#include <QFile>
#include <QFileInfo>

#define BOX_UNDERLYING_DNS dataStore->core_box_underlying_dns.isEmpty() ? "local" : dataStore->core_box_underlying_dns

namespace NekoGui {

    QStringList getAutoBypassExternalProcessPaths(const std::shared_ptr<BuildConfigResult> &result) {
        QStringList paths;
        for (const auto &extR: result->extRs) {
            auto path = extR->program;
            if (path.trimmed().isEmpty()) continue;
            paths << path.replace("\\", "/");
        }
        return paths;
    }

    QString genTunName() {
        auto tun_name = "nekoray-tun";
#ifdef Q_OS_MACOS
        tun_name = "utun9";
#endif
        return tun_name;
    }

    void MergeJson(const QJsonObject &custom, QJsonObject &outbound) {
        // 合并
        if (custom.isEmpty()) return;
        for (const auto &key: custom.keys()) {
            if (outbound.contains(key)) {
                auto v = custom[key];
                auto v_orig = outbound[key];
                if (v.isObject() && v_orig.isObject()) { // isObject 则合并？
                    QJsonObject vo = v.toObject();
                    QJsonObject vo_orig = v_orig.toObject();
                    MergeJson(vo, vo_orig);
                    outbound[key] = vo_orig;
                } else {
                    outbound[key] = v;
                }
            } else {
                outbound[key] = custom[key];
            }
        }
    }

    // Common

    std::shared_ptr<BuildConfigResult> BuildConfig(const std::shared_ptr<ProxyEntity> &ent, bool forTest, bool forExport) {
        auto result = std::make_shared<BuildConfigResult>();
        auto status = std::make_shared<BuildConfigStatus>();
        status->ent = ent;
        status->result = result;
        status->forTest = forTest;
        status->forExport = forExport;

        auto customBean = dynamic_cast<NekoGui_fmt::CustomBean *>(ent->bean.get());
        if (customBean != nullptr && customBean->core == "internal-full") {
            result->coreConfig = QString2QJsonObject(customBean->config_simple);
        } else {
            BuildConfigSingBox(status);
        }

        // apply custom config
        MergeJson(QString2QJsonObject(ent->bean->custom_config), result->coreConfig);

        return result;
    }

    QString BuildChain(int chainId, const std::shared_ptr<BuildConfigStatus> &status) {
        auto group = profileManager->GetGroup(status->ent->gid);
        if (group == nullptr) {
            status->result->error = QString("This profile is not in any group, your data may be corrupted.");
            return {};
        }

        auto resolveChain = [=](const std::shared_ptr<ProxyEntity> &ent) {
            QList<std::shared_ptr<ProxyEntity>> resolved;
            if (ent->type == "chain") {
                auto list = ent->ChainBean()->list;
                std::reverse(std::begin(list), std::end(list));
                for (auto id: list) {
                    resolved += profileManager->GetProfile(id);
                    if (resolved.last() == nullptr) {
                        status->result->error = QString("chain missing ent: %1").arg(id);
                        break;
                    }
                    if (resolved.last()->type == "chain") {
                        status->result->error = QString("chain in chain is not allowed: %1").arg(id);
                        break;
                    }
                }
            } else {
                resolved += ent;
            };
            return resolved;
        };

        // Make list
        auto ents = resolveChain(status->ent);
        if (!status->result->error.isEmpty()) return {};

        if (group->front_proxy_id >= 0) {
            auto fEnt = profileManager->GetProfile(group->front_proxy_id);
            if (fEnt == nullptr) {
                status->result->error = QString("front proxy ent not found.");
                return {};
            }
            ents += resolveChain(fEnt);
            if (!status->result->error.isEmpty()) return {};
        }

        // BuildChain
        QString chainTagOut = BuildChainInternal(0, ents, status);

        // Chain ent traffic stat
        if (ents.length() > 1) {
            status->ent->traffic_data->id = status->ent->id;
            status->ent->traffic_data->tag = chainTagOut.toStdString();
            status->result->outboundStats += status->ent->traffic_data;
        }

        return chainTagOut;
    }

#define DOMAIN_USER_RULE                                                             \
    for (const auto &line: SplitLinesSkipSharp(dataStore->routing->proxy_domain)) {  \
        if (dataStore->routing->dns_routing) status->domainListDNSRemote += line;    \
        status->domainListRemote += line;                                            \
    }                                                                                \
    for (const auto &line: SplitLinesSkipSharp(dataStore->routing->direct_domain)) { \
        if (dataStore->routing->dns_routing) status->domainListDNSDirect += line;    \
        status->domainListDirect += line;                                            \
    }                                                                                \
    for (const auto &line: SplitLinesSkipSharp(dataStore->routing->block_domain)) {  \
        status->domainListBlock += line;                                             \
    }

#define IP_USER_RULE                                                             \
    for (const auto &line: SplitLinesSkipSharp(dataStore->routing->block_ip)) {  \
        status->ipListBlock += line;                                             \
    }                                                                            \
    for (const auto &line: SplitLinesSkipSharp(dataStore->routing->proxy_ip)) {  \
        status->ipListRemote += line;                                            \
    }                                                                            \
    for (const auto &line: SplitLinesSkipSharp(dataStore->routing->direct_ip)) { \
        status->ipListDirect += line;                                            \
    }

    QString BuildChainInternal(int chainId, const QList<std::shared_ptr<ProxyEntity>> &ents,
                               const std::shared_ptr<BuildConfigStatus> &status) {
        QString chainTag = "c-" + Int2String(chainId);
        QString chainTagOut;
        bool muxApplied = false;

        QString pastTag;
        int pastExternalStat = 0;
        int index = 0;

        for (const auto &ent: ents) {
            // tagOut: v2ray outbound tag for a profile
            // profile2 (in) (global)   tag g-(id)
            // profile1                 tag (chainTag)-(id)
            // profile0 (out)           tag (chainTag)-(id) / single: chainTag=g-(id)
            auto tagOut = chainTag + "-" + Int2String(ent->id);

            // needGlobal: can only contain one?
            bool needGlobal = false;

            // first profile set as global
            auto isFirstProfile = index == ents.length() - 1;
            if (isFirstProfile) {
                needGlobal = true;
                tagOut = "g-" + Int2String(ent->id);
            }

            // last profile set as "proxy"
            if (chainId == 0 && index == 0) {
                needGlobal = false;
                tagOut = "proxy";
            }

            // ignoreConnTag
            if (index != 0) {
                status->result->ignoreConnTag << tagOut;
            }

            if (needGlobal) {
                if (status->globalProfiles.contains(ent->id)) {
                    continue;
                }
                status->globalProfiles += ent->id;
            }

            if (index > 0) {
                // chain rules: past
                if (pastExternalStat == 0) {
                    auto replaced = status->outbounds.last().toObject();
                    replaced["detour"] = tagOut;
                    status->outbounds.removeLast();
                    status->outbounds += replaced;
                } else {
                    status->routingRules += QJsonObject{
                        {"inbound", QJsonArray{pastTag + "-mapping"}},
                        {"outbound", tagOut},
                    };
                }
            } else {
                // index == 0 means last profile in chain / not chain
                chainTagOut = tagOut;
                status->result->outboundStat = ent->traffic_data;
            }

            // chain rules: this
            auto ext_mapping_port = 0;
            auto ext_socks_port = 0;
            auto thisExternalStat = ent->bean->NeedExternal(isFirstProfile);
            if (thisExternalStat < 0) {
                status->result->error = "This configuration cannot be set automatically, please try another.";
                return {};
            }

            // determine port
            if (thisExternalStat > 0) {
                if (ent->type == "custom") {
                    auto bean = ent->CustomBean();
                    if (IsValidPort(bean->mapping_port)) {
                        ext_mapping_port = bean->mapping_port;
                    } else {
                        ext_mapping_port = MkPort();
                    }
                    if (IsValidPort(bean->socks_port)) {
                        ext_socks_port = bean->socks_port;
                    } else {
                        ext_socks_port = MkPort();
                    }
                } else {
                    ext_mapping_port = MkPort();
                    ext_socks_port = MkPort();
                }
            }
            if (thisExternalStat == 2) dataStore->need_keep_vpn_off = true;
            if (thisExternalStat == 1) {
                // mapping
                status->inbounds += QJsonObject{
                    {"type", "direct"},
                    {"tag", tagOut + "-mapping"},
                    {"listen", "127.0.0.1"},
                    {"listen_port", ext_mapping_port},
                    {"override_address", ent->bean->serverAddress},
                    {"override_port", ent->bean->serverPort},
                };
                // no chain rule and not outbound, so need to set to direct
                if (isFirstProfile) {
                    status->routingRules += QJsonObject{
                        {"inbound", QJsonArray{tagOut + "-mapping"}},
                        {"outbound", "direct"},
                    };
                }
            }

            // Outbound

            QJsonObject outbound;
            auto stream = GetStreamSettings(ent->bean.get());

            if (thisExternalStat > 0) {
                auto extR = ent->bean->BuildExternal(ext_mapping_port, ext_socks_port, thisExternalStat);
                if (extR.program.isEmpty()) {
                    status->result->error = QObject::tr("Core not found: %1").arg(ent->bean->DisplayCoreType());
                    return {};
                }
                if (!extR.error.isEmpty()) { // rejected
                    status->result->error = extR.error;
                    return {};
                }
                extR.tag = ent->bean->DisplayType();
                status->result->extRs.emplace_back(std::make_shared<NekoGui_fmt::ExternalBuildResult>(extR));

                // SOCKS OUTBOUND
                outbound["type"] = "socks";
                outbound["server"] = "127.0.0.1";
                outbound["server_port"] = ext_socks_port;
            } else {
                const auto coreR = ent->bean->BuildCoreObjSingBox();
                if (coreR.outbound.isEmpty()) {
                    status->result->error = "unsupported outbound";
                    return {};
                }
                if (!coreR.error.isEmpty()) { // rejected
                    status->result->error = coreR.error;
                    return {};
                }
                outbound = coreR.outbound;
            }

            if (ent->type == "wireguard") {
                if (ent->WireGuardBean()->useSystemInterface && !NekoGui::IsAdmin()) {
                    MW_dialog_message("configBuilder", "NeedAdmin");
                    status->result->error = "using wireguard system interface requires elevated permissions";
                    return {};
                }
            }

            // outbound misc
            outbound["tag"] = tagOut;
            ent->traffic_data->id = ent->id;
            ent->traffic_data->tag = tagOut.toStdString();
            status->result->outboundStats += ent->traffic_data;

            // mux common
            auto needMux = ent->type == "vmess" || ent->type == "trojan" || ent->type == "vless" || ent->type == "shadowsocks";
            needMux &= dataStore->mux_concurrency > 0;

            if (stream != nullptr) {
                if (stream->network == "grpc" || stream->network == "quic" || (stream->network == "http" && stream->security == "tls")) {
                    needMux = false;
                }
            }

            auto mux_state = ent->bean->mux_state;
            if (mux_state == 0) {
                if (!dataStore->mux_default_on) needMux = false;
            } else if (mux_state == 1) {
                needMux = true;
            } else if (mux_state == 2) {
                needMux = false;
            }

            if (ent->type == "vless" && outbound["flow"] != "") {
                needMux = false;
            }

            // common
            // apply domain_strategy
            outbound["domain_strategy"] = dataStore->routing->outbound_domain_strategy;
            // apply mux
            if (!muxApplied && needMux) {
                auto muxObj = QJsonObject{
                    {"enabled", true},
                    {"protocol", dataStore->mux_protocol},
                    {"padding", dataStore->mux_padding},
                    {"max_streams", dataStore->mux_concurrency},
                };
                outbound["multiplex"] = muxObj;
                muxApplied = true;
            }

            // apply custom outbound settings
            // MergeJson(QString2QJsonObject(ent->bean->custom_outbound), outbound);

            // Bypass Lookup for the first profile
            auto serverAddress = ent->bean->serverAddress;

            auto customBean = dynamic_cast<NekoGui_fmt::CustomBean *>(ent->bean.get());
            if (customBean != nullptr && customBean->core == "internal") {
                auto server = QString2QJsonObject(customBean->config_simple)["server"].toString();
                if (!server.isEmpty()) serverAddress = server;
            }

            status->outbounds += outbound;
            if (!status->forTest) {
                QJsonObject customOutboundObj = QString2QJsonObject(ent->bean->custom_outbound);
                if (!customOutboundObj.isEmpty()) {
                    status->outbounds += customOutboundObj;
                }
            }
            pastTag = tagOut;
            pastExternalStat = thisExternalStat;
            index++;
        }

        return chainTagOut;
    }

    // SingBox

    void BuildConfigSingBox(const std::shared_ptr<BuildConfigStatus> &status) {
        // Log
        status->result->coreConfig["log"] = QJsonObject{{"level", dataStore->log_level}};

        // Inbounds

        // mixed-in
        if (IsValidPort(dataStore->inbound_socks_port) && !status->forTest) {
            QJsonObject inboundObj;
            inboundObj["tag"] = "mixed-in";
            inboundObj["type"] = "mixed";
            inboundObj["listen"] = dataStore->inbound_address;
            inboundObj["listen_port"] = dataStore->inbound_socks_port;
            if (dataStore->inbound_auth->NeedAuth()) {
                inboundObj["users"] = QJsonArray{
                    QJsonObject{
                        {"username", dataStore->inbound_auth->username},
                        {"password", dataStore->inbound_auth->password},
                    },
                };
            }
            status->inbounds += inboundObj;
        }

        // tun-in
        if (dataStore->spmode_vpn && !status->forTest) {
            QJsonObject inboundObj;
            inboundObj["tag"] = "tun-in";
            inboundObj["type"] = "tun";
            inboundObj["interface_name"] = genTunName();
            inboundObj["auto_route"] = true;
            // inboundObj["endpoint_independent_nat"] = true;
            inboundObj["mtu"] = dataStore->vpn_mtu;
            inboundObj["stack"] = dataStore->vpn_implementation;
            inboundObj["strict_route"] = dataStore->vpn_strict_route;
            inboundObj["address"] = dataStore->vpn_ipv6 ? QJsonArray{"172.18.0.1/30", "fdfe:dcba:9876::1/126"} : QJsonArray{"172.18.0.1/30"};
            status->inbounds += inboundObj;
        }

        // custom inbound
        if (!status->forTest) QJSONARRAY_ADD(status->inbounds, QString2QJsonObject(dataStore->custom_inbound)["inbounds"].toArray())

        // ntp
        if (dataStore->enable_ntp) {
            QJsonObject ntpObj;
            ntpObj["enabled"] = true;
            ntpObj["server"] = dataStore->ntp_server_address;
            ntpObj["server_port"] = dataStore->ntp_server_port;
            ntpObj["interval"] = dataStore->ntp_interval;
            status->result->coreConfig["ntp"] = ntpObj;
        }

        // Outbounds
        auto tagProxy = BuildChain(0, status);
        if (!status->result->error.isEmpty()) return;
        
        status->outbounds += QJsonObject{
            {"type", "direct"},
            {"tag", "direct"},
        };

        // user rule
        if (!status->forTest) {
            DOMAIN_USER_RULE
            IP_USER_RULE
        }

        // sing-box common rule object
        auto make_rule = [&](const QStringList &list, bool isIP = false) {
            QJsonObject rule;
            //
            QJsonArray ip_cidr;
            QJsonArray geoip;
            //
            QJsonArray domain_keyword;
            QJsonArray domain_subdomain;
            QJsonArray domain_regexp;
            QJsonArray domain_full;
            QJsonArray geosite;
            for (auto item: list) {
                if (isIP) {
                    if (item.startsWith("geoip:")) {
                        geoip += item.replace("geoip:", "");
                    } else {
                        ip_cidr += item;
                    }
                } else {
                    // https://www.v2fly.org/config/dns.html#dnsobject
                    if (item.startsWith("geosite:")) {
                        geosite += item.replace("geosite:", "");
                    } else if (item.startsWith("full:")) {
                        domain_full += item.replace("full:", "").toLower();
                    } else if (item.startsWith("domain:")) {
                        domain_subdomain += item.replace("domain:", "").toLower();
                    } else if (item.startsWith("regexp:")) {
                        domain_regexp += item.replace("regexp:", "").toLower();
                    } else if (item.startsWith("keyword:")) {
                        domain_keyword += item.replace("keyword:", "").toLower();
                    } else {
                        domain_full += item.toLower();
                    }
                }
            }
            if (isIP) {
                if (ip_cidr.isEmpty() && geoip.isEmpty()) return rule;
                rule["ip_cidr"] = ip_cidr;
                rule["geoip"] = geoip;
            } else {
                if (domain_keyword.isEmpty() && domain_subdomain.isEmpty() && domain_regexp.isEmpty() && domain_full.isEmpty() && geosite.isEmpty()) {
                    return rule;
                }
                rule["domain"] = domain_full;
                rule["domain_suffix"] = domain_subdomain; // v2ray Subdomain => sing-box suffix
                rule["domain_keyword"] = domain_keyword;
                rule["domain_regex"] = domain_regexp;
                rule["geosite"] = geosite;
            }
            return rule;
        };

        // DNS
        QJsonObject dns;
        QJsonArray dnsServers;
        QJsonArray dnsRules;

        // Remote
        if (!status->forTest)
            dnsServers += QJsonObject{
                {"tag", "dns-remote"},
                {"address_resolver", "dns-local"},
                {"strategy", dataStore->routing->remote_dns_strategy},
                {"address", dataStore->routing->remote_dns},
                {"detour", tagProxy},
            };

        // Direct
        auto directDNSAddress = dataStore->routing->direct_dns;
        QJsonObject directObj{
            {"tag", "dns-direct"},
            {"address_resolver", "dns-local"},
            {"strategy", dataStore->routing->direct_dns_strategy},
            {"address", directDNSAddress.replace("+local://", "://")},
            {"detour", "direct"},
        };
        if (dataStore->routing->dns_final_out == "direct") {
            dnsServers.prepend(directObj);
        } else {
            dnsServers.append(directObj);
        }

        // Underlying 100% Working DNS
        dnsServers += QJsonObject{
            {"tag", "dns-local"},
            {"address", BOX_UNDERLYING_DNS},
            {"detour", "direct"},
        };

        // Fakedns
        if (dataStore->routing->fake_dns && !status->forTest) {
            dnsServers += QJsonObject{
                {"tag", "dns-fake"},
                {"type", "fakeip"},
                {"inet4_range", "198.18.0.0/15"},
                {"inet6_range", "fc00::/18"},
            };
            dnsRules += QJsonObject{
                {"query_type", QJsonArray{"A", "AAAA"}},
                {"server", "dns-fake"}};
            dns["independent_cache"] = true;
        }

        // Dns Rules

        // serverAddress dns rule
        dnsRules += QJsonObject{
            {"outbound", "any"},
            {"server", "dns-direct"},
        };

        auto add_rule_dns = [&](const QStringList &list, const QString &server) {
            auto rule = make_rule(list, false);
            if (rule.isEmpty()) return;
            rule["server"] = server;
            dnsRules += rule;
        };
        if (!status->forTest) {
            add_rule_dns(status->domainListDNSRemote, "dns-remote");
            add_rule_dns(status->domainListDNSDirect, "dns-direct");
        }

        dns["servers"] = dnsServers;
        dns["rules"] = dnsRules;
        dns["reverse_mapping"] = true;

        if (dataStore->routing->use_dns_object && !status->forTest) {
            dns = QString2QJsonObject(dataStore->routing->dns_object);
        }

        // Routing
        QJsonObject routeObj;

        // Rules
        if (!status->forTest) {
            if(dataStore->routing->domain_strategy!=""){
                status->routingRules += QJsonObject{
                    {"action", "resolve"}
                };
            }
            if (dataStore->routing->sniffing_mode != SniffingMode::DISABLE) {
                status->routingRules += QJsonObject{
                    {"action", "sniff"}
                };
            }
            status->routingRules += QJsonObject{
                {"action", "hijack-dns"},
                {"mode", "or"},
                {"type", "logical"},
                {"rules", QJsonArray{
                    QJsonObject{{"port", 53}},
                    QJsonObject{{"protocol", "dns"}}
                }}
            };
        }

        // sing-box routing rule object
        auto add_rule_route = [&](const QStringList &list, bool isIP, const QString &out) {
            auto rule = make_rule(list, isIP);
            if (rule.isEmpty()) return;
            rule["outbound"] = out;
            status->routingRules += rule;
        };

        // final add user rule
        add_rule_route(status->domainListBlock, false, "block");
        add_rule_route(status->domainListRemote, false, tagProxy);
        add_rule_route(status->domainListDirect, false, "direct");
        add_rule_route(status->ipListBlock, true, "block");
        add_rule_route(status->ipListRemote, true, tagProxy);
        add_rule_route(status->ipListDirect, true, "direct");

        // tun user rule
        if (dataStore->spmode_vpn && !status->forTest) {
            auto match_out = dataStore->vpn_rule_white ? "proxy" : "direct";

            QString process_name_rule = dataStore->vpn_rule_process.trimmed();
            if (!process_name_rule.isEmpty()) {
                auto arr = SplitLinesSkipSharp(process_name_rule);
                QJsonObject rule{{"outbound", match_out},
                                 {"process_name", QList2QJsonArray(arr)}};
                status->routingRules += rule;
            }

            QString cidr_rule = dataStore->vpn_rule_cidr.trimmed();
            if (!cidr_rule.isEmpty()) {
                auto arr = SplitLinesSkipSharp(cidr_rule);
                QJsonObject rule{{"outbound", match_out},
                                 {"ip_cidr", QList2QJsonArray(arr)}};
                status->routingRules += rule;
            }

            auto autoBypassExternalProcessPaths = getAutoBypassExternalProcessPaths(status->result);
            if (!autoBypassExternalProcessPaths.isEmpty()) {
                QJsonObject rule{{"outbound", "direct"},
                                 {"process_name", QList2QJsonArray(autoBypassExternalProcessPaths)}};
                status->routingRules += rule;
            }
        }

        // geopath
        auto geoip = FindCoreAsset("geoip.db");
        auto geosite = FindCoreAsset("geosite.db");
        if (geoip.isEmpty()) status->result->error = +"geoip.db not found";
        if (geosite.isEmpty()) status->result->error = +"geosite.db not found";

        if (!status->forTest) {
            auto custom_routeObj = QString2QJsonObject(dataStore->routing->custom);
            if (custom_routeObj.isEmpty()) {
                routeObj = QJsonObject{
                    {"rules", status->routingRules},
                    {"final", dataStore->routing->def_outbound},
                    // {"default_domain_resolver", QJsonObject{{"server", "dns-direct"}}},
                    {"geoip", QJsonObject{{"path", geoip}}},
                    {"geosite", QJsonObject{{"path", geosite}}}};
                if (dataStore->spmode_vpn) routeObj["auto_detect_interface"] = true;
            } else {
                auto outboundsArray = custom_routeObj["outbounds"].toArray();
                if (!outboundsArray.isEmpty())
                    for (const auto& outbound : outboundsArray) {
                        status->outbounds.append(outbound);
                    }
                routeObj = custom_routeObj["route"].toObject();
            }
        }
        // if (status->forExport) {
        //     routeObj.remove("geoip");
        //     routeObj.remove("geosite");
        //     routeObj.remove("auto_detect_interface");
        // }

        // experimental
        QJsonObject experimentalObj;
        if (!status->forTest && dataStore->core_box_clash_api > 0) {
            QJsonObject clash_api = {
                {"external_controller", NekoGui::dataStore->core_box_clash_listen_addr + ":" + Int2String(dataStore->core_box_clash_api)},
                {"secret", dataStore->core_box_clash_api_secret},
                {"external_ui", "dashboard"},
            };
            experimentalObj["clash_api"] = clash_api;
        }

        status->result->coreConfig.insert("dns", dns);
        status->result->coreConfig.insert("inbounds", status->inbounds);
        status->result->coreConfig.insert("outbounds", status->outbounds);
        status->result->coreConfig.insert("route", routeObj);
        if (!experimentalObj.isEmpty()) status->result->coreConfig.insert("experimental", experimentalObj);
    }

    QString WriteVPNSingBoxConfig() {
        // tun user rule
        auto match_out = dataStore->vpn_rule_white ? "nekoray-socks" : "direct";
        auto no_match_out = dataStore->vpn_rule_white ? "direct" : "nekoray-socks";

        QString process_name_rule = dataStore->vpn_rule_process.trimmed();
        if (!process_name_rule.isEmpty()) {
            auto arr = SplitLinesSkipSharp(process_name_rule);
            QJsonObject rule{{"outbound", match_out},
                             {"process_name", QList2QJsonArray(arr)}};
            process_name_rule = "," + QJsonObject2QString(rule, false);
        }

        QString cidr_rule = dataStore->vpn_rule_cidr.trimmed();
        if (!cidr_rule.isEmpty()) {
            auto arr = SplitLinesSkipSharp(cidr_rule);
            QJsonObject rule{{"outbound", match_out},
                             {"ip_cidr", QList2QJsonArray(arr)}};
            cidr_rule = "," + QJsonObject2QString(rule, false);
        }

        // TODO bypass ext core process path?

        // auth
        QString socks_user_pass;
        if (dataStore->inbound_auth->NeedAuth()) {
            socks_user_pass = R"( "username": "%1", "password": "%2", )";
            socks_user_pass = socks_user_pass.arg(dataStore->inbound_auth->username, dataStore->inbound_auth->password);
        }
        // gen config
        auto configFn = ":/neko/vpn/sing-box-vpn.json";
        if (QFile::exists("vpn/sing-box-vpn.json")) configFn = "vpn/sing-box-vpn.json";
        auto config = ReadFileText(configFn)
                          .replace("//%IPV6_ADDRESS%", dataStore->vpn_ipv6 ? R"("inet6_address": "fdfe:dcba:9876::1/126",)" : "")
                          .replace("//%SOCKS_USER_PASS%", socks_user_pass)
                          .replace("//%PROCESS_NAME_RULE%", process_name_rule)
                          .replace("//%CIDR_RULE%", cidr_rule)
                          .replace("%MTU%", Int2String(dataStore->vpn_mtu))
                          .replace("%STACK%", dataStore->vpn_implementation)
                          .replace("%TUN_NAME%", genTunName())
                          .replace("%STRICT_ROUTE%", dataStore->vpn_strict_route ? "true" : "false")
                          .replace("%FINAL_OUT%", no_match_out)
                          .replace("%DNS_ADDRESS%", BOX_UNDERLYING_DNS)
                          .replace("%PORT%", Int2String(dataStore->inbound_socks_port));
        // write config
        QFile file;
        file.setFileName(QFileInfo(configFn).fileName());
        file.open(QIODevice::ReadWrite | QIODevice::Truncate);
        file.write(config.toUtf8());
        file.close();
        return QFileInfo(file).absoluteFilePath();
    }

    QString WriteVPNLinuxScript(const QString &protectPath, const QString &configPath) {
#ifdef Q_OS_WIN
        return {};
#endif
        // gen script
        auto scriptFn = ":/neko/vpn/vpn-run-root.sh";
        if (QFile::exists("vpn/vpn-run-root.sh")) scriptFn = "vpn/vpn-run-root.sh";
        auto script = ReadFileText(scriptFn)
                          .replace("./nekobox_core", QApplication::applicationDirPath() + "/nekobox_core")
                          .replace("$PROTECT_LISTEN_PATH", protectPath)
                          .replace("$CONFIG_PATH", configPath)
                          .replace("$TABLE_FWMARK", "514");
        // write script
        QFile file2;
        file2.setFileName(QFileInfo(scriptFn).fileName());
        file2.open(QIODevice::ReadWrite | QIODevice::Truncate);
        file2.write(script.toUtf8());
        file2.close();
        return QFileInfo(file2).absoluteFilePath();
    }

} // namespace NekoGui