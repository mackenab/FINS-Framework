#ifndef GUICOMM_MW_H
#define GUICOMM_MW_H

#include <QMainWindow>
#include <libconfig.h++>
#include "module.h"
#include "/home/dell-kevin/FINS-Framework/FINSCore/fins_headers/finstypes.h"     //include this in the documentation.

using namespace libconfig;

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void loadConfig();

protected:
    void changeEvent(QEvent *e);

private:
    Ui::MainWindow *ui;
    QString selected_module_qs;
    QString selected_param;
    QString selected_operation;
    finsFrame * FCF_write_request;
    finsFrame * FCF_write_reply;    //This name should be changed to read_reply
    finsFrame * FCF_read_request;
    Config cfg;
    QWidget widget;
    QMap<int,module> mod_map;   //contains all of the different modules held in the config files
    module selected_module_m;   //represents the module selected in the combobox

    bool readytoSend();
    void sendtoFINS();
    void print_Status(QString );
    void print_Error(QString );


private slots:
    void on_value_le_textEdited(QString );
    void on_actionQuit_triggered();
    void on_operation_cb_activated(QString );
    void on_param_cb_activated(QString );
    void on_setparam_pb_clicked();
    void on_module_cb_activated(QString );
};
#endif // GUICOMM_MW_H
