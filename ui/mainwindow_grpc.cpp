#include "./ui_mainwindow.h"
#include "mainwindow.h"

#include "db/Database.hpp"
#include "db/ConfigBuilder.hpp"
#include "db/traffic/TrafficLooper.hpp"
#include "ui/widget/MessageBoxTimer.h"

#include "libbox.h"

#include <QTimer>
#include <QThread>
#include <QInputDialog>
#include <QPushButton>
#include <QDesktopServices>
#include <QMessageBox>
#include <QDialogButtonBox>

// ext core

std::list<std::shared_ptr<NekoGui_sys::ExternalProcess>> CreateExtCFromExtR(const std::list<std::shared_ptr<NekoGui_fmt::ExternalBuildResult>> &extRs, bool start) {
    // plz run and start in same thread
    std::list<std::shared_ptr<NekoGui_sys::ExternalProcess>> l;
    for (const auto &extR: extRs) {
        std::shared_ptr<NekoGui_sys::ExternalProcess> extC(new NekoGui_sys::ExternalProcess());
        extC->tag = extR->tag;
        extC->program = extR->program;
        extC->arguments = extR->arguments;
        extC->env = extR->env;
        l.emplace_back(extC);
        //
        if (start) extC->Start();
    }
    return l;
}

// grpc

// using namespace NekoGui_rpc;

void MainWindow::setup_grpc() {
    // // Setup Connection
    // defaultClient = new Client(
    //     [=](const QString &errStr) {
    //         MW_show_log("[Error] gRPC: " + errStr);
    //     },
    //     "127.0.0.1:" + Int2String(NekoGui::dataStore->core_port), NekoGui::dataStore->core_token);

    // Looper
    runOnNewThread([=] { NekoGui_traffic::trafficLooper->Loop(); });
}

// 测速

inline bool speedtesting = false;
inline QList<QThread *> speedtesting_threads = {};

void MainWindow::speedtest_current_group(int mode) {
    auto profiles = get_selected_or_group();
    if (profiles.isEmpty()) return;
    auto group = NekoGui::profileManager->CurrentGroup();
    if (group->archive) return;

    // menu_stop_testing
    if (mode == 114514) {
        while (!speedtesting_threads.isEmpty()) {
            auto t = speedtesting_threads.takeFirst();
            if (t != nullptr) t->exit();
        }
        speedtesting_threads.clear();
        speedtesting = false;
        return;
    }

    if (speedtesting) {
        MessageBoxWarning(software_name, "The last speed test did not exit completely, please wait. If it persists, please restart the program.");
        return;
    }
    QList<int> full_test_flags;
    if (mode == 999) {
        auto w = new QDialog(this);
        auto layout = new QVBoxLayout(w);
        w->setWindowTitle(tr("Test Options"));
        //
        auto l1 = new QCheckBox(tr("Latency"));
        auto l2 = new QCheckBox(tr("UDP latency"));
        auto l3 = new QCheckBox(tr("Download speed"));
        auto l4 = new QCheckBox(tr("In and Out IP"));
        //
        auto box = new QDialogButtonBox;
        box->setOrientation(Qt::Horizontal);
        box->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
        connect(box, &QDialogButtonBox::accepted, w, &QDialog::accept);
        connect(box, &QDialogButtonBox::rejected, w, &QDialog::reject);
        //
        layout->addWidget(l1);
        layout->addWidget(l2);
        layout->addWidget(l3);
        layout->addWidget(l4);
        layout->addWidget(box);
        if (w->exec() != QDialog::Accepted) {
            w->deleteLater();
            return;
        }
        //
        if (l1->isChecked()) full_test_flags << UrlTest;
        if (l2->isChecked()) full_test_flags << UdpTest;
        if (l3->isChecked()) full_test_flags << SpeedTest;
        if (l4->isChecked()) full_test_flags << IpTest;
        //
        w->deleteLater();
        if (full_test_flags.isEmpty()) return;
    } else {
        full_test_flags << mode;
    }
    speedtesting = true;

    runOnNewThread([this, profiles, full_test_flags] {
        QMutex lock_write;
        QMutex lock_return;
        int threadN = qMin(NekoGui::dataStore->test_concurrent, profiles.count());
        auto profiles_test = profiles; // copy

        // Threads
        lock_return.lock();
        for (int i = 0; i < threadN; ++i) {
            runOnNewThread([&] {
                lock_write.lock();
                speedtesting_threads << QObject::thread();
                lock_write.unlock();

                forever {
                    //
                    lock_write.lock();
                    if (profiles_test.isEmpty()) {
                        speedtesting_threads.removeOne(QObject::thread());
                        if (speedtesting_threads.isEmpty()) {
                            // quit control thread
                            lock_write.unlock();
                            lock_return.unlock();
                            return;
                        }
                        // quit of this thread
                        lock_write.unlock();
                        return;
                    }
                    auto profile = profiles_test.takeFirst();
                    lock_write.unlock();

                    std::list<std::shared_ptr<NekoGui_sys::ExternalProcess>> extCs;
                    QSemaphore extSem;

                    int Timeout = 3000;
                    QByteArray CoreConfig;
                    QByteArray Address;
                    QByteArray Url;
                    if (!full_test_flags.contains(TcpPing)) {
                        auto c = BuildConfig(profile, true, false);
                        if (!c->error.isEmpty()) {
                            profile->full_test_report = c->error;
                            profile->Save();
                            auto profileId = profile->id;
                            runOnUiThread([this, profileId] {
                                refresh_proxy_list(profileId);
                            });
                            continue;
                        }
                        if (!c->extRs.empty()) {
                            runOnUiThread(
                                [&] {
                                    extCs = CreateExtCFromExtR(c->extRs, true);
                                    QThread::msleep(500);
                                    extSem.release();
                                },
                                DS_cores);
                            extSem.acquire();
                        }
                        CoreConfig = QJsonObject2QString(c->coreConfig, false).toUtf8();
                    }
                    QStringList full_test_result;
                    bool testOK;
                    for (int Mode: full_test_flags) {
                        if (Mode == TcpPing) {
                            Address = profile->bean->DisplayAddress().toUtf8();
                        } else if (Mode == UrlTest) {
                            Url = NekoGui::dataStore->test_latency_url.toUtf8();
                        } else if (Mode == SpeedTest) {
                            Url = NekoGui::dataStore->test_download_url.toUtf8();
                            Timeout = NekoGui::dataStore->test_download_timeout;
                        } else if (Mode == IpTest) {
                            Address = profile->bean->serverAddress.toUtf8();
                        }
                        auto boxTestResult = BoxTest(Mode, Timeout, CoreConfig.data(), Address.data(), Url.data());
                        QString testResult(boxTestResult);
                        free(boxTestResult);

                        if (full_test_flags.count() == 1 && (Mode == TcpPing || Mode == UrlTest || Mode == UdpTest)) {
                            // SpeedTest很不准确不适合排序比较
                            profile->full_test_report.clear();
                            profile->latency = testResult.toInt(&testOK);
                            if (profile->latency == 0) profile->latency = 1;
                            if (!testOK) {
                                profile->latency = -1;
                                MW_show_log(tr("[%1] test error: %2").arg(profile->bean->DisplayTypeAndName(), testResult));
                            }
                        } else if (Mode == UrlTest) {
                            testResult.toInt(&testOK);
                            if (testOK)
                                full_test_result.append("Latency: " + testResult + " ms");
                            else
                                full_test_result.append("Latency: Error");
                        } else if (Mode == UdpTest) {
                            testResult.toInt(&testOK);
                            if (testOK)
                                full_test_result.append("UDPLatency: " + testResult + " ms");
                            else
                                full_test_result.append("UDPLatency: Error");
                        } else if (Mode == SpeedTest) {
                            testResult.toFloat(&testOK);
                            if (testOK)
                                full_test_result.append("Speed: " + testResult + " MiB/s");
                            else
                                full_test_result.append("Speed: Error");
                        } else if (Mode == IpTest) {
                            full_test_result.append(testResult);
                        }
                    }

                    // if (result.error().empty()) {
                    //     profile->latency = result.ms();
                    //     if (profile->latency == 0) profile->latency = 1; // nekoray use 0 to represents not tested
                    // } else {
                    //     profile->latency = -1;
                    // }
                    if (!full_test_result.isEmpty()) profile->full_test_report = full_test_result.join("/"); // higher priority
                    profile->Save();

                    // if (!result.error().empty()) {
                    //     MW_show_log(tr("[%1] test error: %2").arg(profile->bean->DisplayTypeAndName(), result.error().c_str()));
                    // }

                    auto profileId = profile->id;
                    runOnUiThread([this, profileId] {
                        refresh_proxy_list(profileId);
                    });
                }
            });
        }
        // Control
        lock_return.lock();
        lock_return.unlock();
        speedtesting = false;
    });
}

void MainWindow::speedtest_current() {
    last_test_time = QTime::currentTime();
    ui->label_running->setText(tr("Testing"));

    runOnNewThread([=] {
        auto Url = NekoGui::dataStore->test_latency_url.toUtf8();
        auto boxTestResult = BoxTest(UrlTest, 3000, nullptr, nullptr, Url.data());
        QString testResult(boxTestResult);
        free(boxTestResult);
        last_test_time = QTime::currentTime();

        bool testOK;
        testResult.toInt(&testOK);
        if (testOK)
            ui->label_running->setText(tr("Test Result") + ": " + testResult + " ms");
        else {
            ui->label_running->setText(tr("Test Result") + ": " + tr("Unavailable"));
            MW_show_log(QString("UrlTest : %1").arg(testResult));
        }
    });
}

void MainWindow::neko_start(int _id) {
    if (NekoGui::dataStore->prepare_exit) return;

    auto ents = get_now_selected_list();
    auto ent = (_id < 0 && !ents.isEmpty()) ? ents.first() : NekoGui::profileManager->GetProfile(_id);
    if (ent == nullptr) return;

    if (select_mode) {
        emit profile_selected(ent->id);
        select_mode = false;
        refresh_status();
        return;
    }

    auto group = NekoGui::profileManager->GetGroup(ent->gid);
    if (group == nullptr || group->archive) return;

    auto result = BuildConfig(ent, false, false);
    if (!result->error.isEmpty()) {
        MessageBoxWarning("BuildConfig return error", result->error);
        return;
    }

    auto neko_start_stage2 = [=] {
        auto CoreConfig = QJsonObject2QString(result->coreConfig, false).toUtf8();
        auto BoxStartError = BoxStart(CoreConfig.data(), NekoGui::dataStore->disable_traffic_stats);
        if (BoxStartError != nullptr) {
            QString boxStartError(BoxStartError);
            free(BoxStartError);
            MW_show_log(boxStartError);
            if (boxStartError.contains("configure tun interface")) {
                runOnUiThread([=] {
                    auto r = QMessageBox::information(this, tr("Tun device misbehaving"),
                                                      tr("If you have trouble starting VPN, you can force reset nekobox_core process here and then try starting the profile again."),
                                                      tr("Reset"), tr("Cancel"), "",
                                                      1, 1);
                    if (r == 0) {
                        GetMainWindow()->StopVPNProcess(true);
                    }
                });
                return false;
            }
            runOnUiThread([=] { MessageBoxWarning("LoadConfig return error", boxStartError); });
            return false;
        }
        //
        NekoGui_traffic::trafficLooper->proxy = result->outboundStat.get();
        NekoGui_traffic::trafficLooper->items = result->outboundStats;
        NekoGui::dataStore->ignoreConnTag = result->ignoreConnTag;
        NekoGui_traffic::trafficLooper->loop_enabled = true;

        runOnUiThread(
            [=] {
                auto extCs = CreateExtCFromExtR(result->extRs, true);
                NekoGui_sys::running_ext.splice(NekoGui_sys::running_ext.end(), extCs);
            },
            DS_cores);

        NekoGui::dataStore->UpdateStartedId(ent->id);
        running = ent;

        runOnUiThread([=] {
            refresh_status();
            refresh_proxy_list(ent->id);
        });

        return true;
    };

    if (!mu_starting.tryLock()) {
        MessageBoxWarning(software_name, "Another profile is starting...");
        return;
    }
    if (!mu_stopping.tryLock()) {
        MessageBoxWarning(software_name, "Another profile is stopping...");
        mu_starting.unlock();
        return;
    }
    mu_stopping.unlock();

    // // check core state
    // if (!NekoGui::dataStore->core_running) {
    //     runOnUiThread(
    //         [=] {
    //             MW_show_log("Try to start the config, but the core has not listened to the grpc port, so restart it...");
    //             core_process->start_profile_when_core_is_up = ent->id;
    //             core_process->Restart();
    //         },
    //         DS_cores);
    //     mu_starting.unlock();
    //     return; // let CoreProcess call neko_start when core is up
    // }

    // timeout message
    auto restartMsgbox = new QMessageBox(QMessageBox::Question, software_name, tr("If there is no response for a long time, it is recommended to restart the software."),
                                         QMessageBox::Yes | QMessageBox::No, this);
    connect(restartMsgbox, &QMessageBox::accepted, this, [=] { MW_dialog_message("", "RestartProgram"); });
    auto restartMsgboxTimer = new MessageBoxTimer(this, restartMsgbox, 5000);

    runOnNewThread([=] {
        // stop current running
        if (NekoGui::dataStore->started_id >= 0) {
            runOnUiThread([=] { neko_stop(false, true); });
            sem_stopped.acquire();
        }
        // do start
        MW_show_log(">>>>>>>> " + tr("Starting profile %1").arg(ent->bean->DisplayTypeAndName()));
        if (!neko_start_stage2()) {
            MW_show_log("<<<<<<<< " + tr("Failed to start profile %1").arg(ent->bean->DisplayTypeAndName()));
        }
        mu_starting.unlock();
        // cancel timeout
        runOnUiThread([=] {
            restartMsgboxTimer->cancel();
            restartMsgboxTimer->deleteLater();
            restartMsgbox->deleteLater();
#ifdef Q_OS_LINUX
            // Check systemd-resolved
            if (NekoGui::dataStore->spmode_vpn && NekoGui::dataStore->routing->direct_dns.startsWith("local") && ReadFileText("/etc/resolv.conf").contains("systemd-resolved")) {
                MW_show_log("[Warning] The default Direct DNS may not works with systemd-resolved, you may consider change your DNS settings.");
            }
#endif
        });
    });
}

void MainWindow::neko_stop(bool crash, bool sem) {
    auto id = NekoGui::dataStore->started_id;
    if (id < 0) {
        if (sem) sem_stopped.release();
        return;
    }

    auto neko_stop_stage2 = [=] {
        runOnUiThread(
            [=] {
                while (!NekoGui_sys::running_ext.empty()) {
                    auto extC = NekoGui_sys::running_ext.front();
                    extC->Kill();
                    NekoGui_sys::running_ext.pop_front();
                }
            },
            DS_cores);

        NekoGui_traffic::trafficLooper->loop_enabled = false;
        NekoGui_traffic::trafficLooper->loop_mutex.lock();
        if (NekoGui::dataStore->traffic_loop_interval != 0) {
            NekoGui_traffic::trafficLooper->UpdateAll();
            for (const auto &item: NekoGui_traffic::trafficLooper->items) {
                NekoGui::profileManager->GetProfile(item->id)->Save();
                runOnUiThread([=] { refresh_proxy_list(item->id); });
            }
        }
        NekoGui_traffic::trafficLooper->loop_mutex.unlock();

        if (!crash) {
            BoxStop();
        }

        NekoGui::dataStore->UpdateStartedId(-1919);
        NekoGui::dataStore->need_keep_vpn_off = false;
        running = nullptr;

        runOnUiThread([=] {
            refresh_status();
            refresh_proxy_list(id);
        });

        return true;
    };

    if (!mu_stopping.tryLock()) {
        if (sem) sem_stopped.release();
        return;
    }

    // timeout message
    auto restartMsgbox = new QMessageBox(QMessageBox::Question, software_name, tr("If there is no response for a long time, it is recommended to restart the software."),
                                         QMessageBox::Yes | QMessageBox::No, this);
    connect(restartMsgbox, &QMessageBox::accepted, this, [=] { MW_dialog_message("", "RestartProgram"); });
    auto restartMsgboxTimer = new MessageBoxTimer(this, restartMsgbox, 5000);

    // do stop
    MW_show_log(">>>>>>>> " + tr("Stopping profile %1").arg(running->bean->DisplayTypeAndName()));
    if (!neko_stop_stage2()) {
        MW_show_log("<<<<<<<< " + tr("Failed to stop, please restart the program."));
    }
    mu_stopping.unlock();
    if (sem) sem_stopped.release();
    // cancel timeout
    runOnUiThread([=] {
        restartMsgboxTimer->cancel();
        restartMsgboxTimer->deleteLater();
        restartMsgbox->deleteLater();
    });
}

void MainWindow::CheckUpdate() {
    return;
}
