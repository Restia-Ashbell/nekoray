#pragma once

#include <QWidget>
#include "profile_editor.h"

QT_BEGIN_NAMESPACE
namespace Ui {
    class EditSSH;
}
QT_END_NAMESPACE

class EditSSH : public QWidget, public ProfileEditor {
    Q_OBJECT

public:
    explicit EditSSH(QWidget *parent = nullptr);

    ~EditSSH() override;

    void onStart(std::shared_ptr<NekoGui::ProxyEntity> _ent) override;

    bool onEnd() override;

private:
    Ui::EditSSH *ui;
    std::shared_ptr<NekoGui::ProxyEntity> ent;
};