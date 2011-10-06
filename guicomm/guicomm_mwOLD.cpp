#include "guicomm_mw.h"
#include "ui_guicomm_mw.h"
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <QTextStream>
#include <QMessageBox>
#include "/home/dell-kevin/FINS-Framework/FINSCore/fins_headers/finstypes.h"     //include this in the documentation.
#include "module.h"


//defines the locations of the two pipes
#define RTM_PIPE_IN "/tmp/fins/rtm_in"
#define RTM_PIPE_OUT "/tmp/fins/rtm_out"

//defines the finsFrame elements used for MileStone 1, more can be found in finstypes.h
/*
//obsolete due to finstypes.h being included
#define WRITEREQUEST 333
#define CONTROL 1
#define UDPID 44
#define DUMMYA 123
#define DUMMYB 456
#define DUMMYC 789
*/

QTextStream debug(stdout);
using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{

    try
    {
        cfg.readFile("guicomm.cfg");
    }
    catch (ParseException e)
    {
        debug << "An exception occurred: " << e.getError() << endl;
    }
    loadConfig();

    FCF_write_request.dataOrCtrl = 1;

    ui->setupUi(this);
    ui->setparam_pb->setEnabled(false);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
    switch (e->type())
    {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void MainWindow::on_module_cb_activated(QString selected)
{
    selected_module = selected;
    ui->param_cb->clear();

    if(selected == "<Select>")
    {
        ui->param_cb->addItem("Empty");
    }
    else if(selected == "UDP")
    {
        ui->param_cb->addItem("Packet length (Logging only)");         //Logging only
        ui->param_cb->addItem("Dummy Parameter A");
        ui->param_cb->addItem("Dummy Parameter B");
        ui->param_cb->addItem("Dummy Parameter C");
    }
    else if(selected == "IPv4")
    {
        ui->param_cb->addItem("Time to Live (Logging only)");           //Logging only
    }

    readytoSend();
}

void MainWindow::on_param_cb_activated(QString selected)
{
    selected_param = selected;
}

void MainWindow::on_setparam_pb_clicked()
{
    FCF_write_request.parameterValue = (int*)ui->value_le->text().toInt();

    if(selected_module == "UDP")
    {
        FCF_write_request.destinationID_id = UDPID;

        if(selected_param == "Dummy Parameter A")
        {
            FCF_write_request.paramterID = DUMMYA;
        }
        else if(selected_param == "Dummy Parameter B")
        {
            FCF_write_request.paramterID = DUMMYB;
        }
        else if(selected_param == "Dummy Parameter C")
        {
            FCF_write_request.paramterID = DUMMYC;
        }
        if(selected_operation == "Write")
        {
            FCF_write_request.opcode = WRITEREQUEST;
        }

        ui->setparam_pb->setEnabled(false);
        ui->value_le->setText("");


        sendtoFINS();

    }
    else
    {
        print_Error("Incorrect feild combination");
    }

    readytoSend();
}


void MainWindow::on_operation_cb_activated(QString selected)
{
    selected_operation = selected;

    readytoSend();
}

void MainWindow::on_actionQuit_triggered()
{
    this->close();
}

bool MainWindow::readytoSend()
{
    if((selected_module == "UDP") && (FCF_write_request.paramterID) && (selected_operation == "Write") && (ui->value_le->text() != ""))
    {

        ui->setparam_pb->setEnabled(true);
        print_Status("The value is ready to be written");

        return true;
    }
    else
    {
        return false;
    }
}

void MainWindow::sendtoFINS()
{

    //Initializations
    int rtm_in_fd;		//fildes (unistd.h) used for write()
    int rtm_out_fd;		//fildes (unistd.h)
    int numBytes;
    QMessageBox mb;
    QString dataOrCtrl_qs;
    QString destinationID_qs;
    QString opcode_qs;
    QString senderID_qs;
    QString serialNum_qs;


    //open the pipe
    rtm_in_fd = open(RTM_PIPE_IN, O_RDWR);
    rtm_out_fd = open(RTM_PIPE_OUT, O_RDWR);

    if (rtm_in_fd == -1)
    {
            print_Error("rtm_in_fd Pipe failure "); //rtm_out_fd???
            exit(EXIT_FAILURE);
    }


    //SEND OVER PIPE RTM_IN
    //DOCUMENT THIS FORMAT
    numBytes = 0;
    numBytes += write(rtm_in_fd, &FCF_write_request.dataOrCtrl, sizeof(unsigned char));
    numBytes += write(rtm_in_fd, &FCF_write_request.destinationID_id, sizeof(unsigned char));
    numBytes += write(rtm_in_fd, &FCF_write_request.opcode, sizeof(unsigned short int));
    numBytes += write(rtm_in_fd, &FCF_write_request.paramterID, sizeof(unsigned int));
    numBytes += write(rtm_in_fd, &FCF_write_request.senderID, sizeof(unsigned char));
    numBytes += write(rtm_in_fd, &FCF_write_request.parameterValue, sizeof(int));	//sends it over as a int

    //READ FROM PIPE RTM_OUT
    //|| Data/Control | Destination_IDs_List | SenderID | Write_parameter_Confirmation_Code | Serial_Number ||
    numBytes = 0;
    numBytes += read(rtm_out_fd, &FCF_write_reply.dataOrCtrl, sizeof(unsigned char));			//control_data
    numBytes += read(rtm_out_fd, &FCF_write_reply.destinationID_id, sizeof(unsigned char));		//destinationID
    numBytes += read(rtm_out_fd, &FCF_write_reply.senderID, sizeof(unsigned char));			//senderID
    numBytes += read(rtm_out_fd, &FCF_write_reply.opcode, sizeof(unsigned short int));			//opcode
    numBytes += read(rtm_out_fd, &FCF_write_reply.serialNum, sizeof(unsigned int));			//serialNum


    dataOrCtrl_qs = QString::number(FCF_write_reply.dataOrCtrl);
    destinationID_qs = QString::number(FCF_write_reply.destinationID_id);
    opcode_qs = QString::number(FCF_write_reply.opcode);
    senderID_qs = QString::number(FCF_write_reply.senderID);
    serialNum_qs = QString::number(FCF_write_reply.serialNum);

    //Pop-up dialog
    mb.setText("Parameter has been set!");
    mb.setDetailedText("FCF: dataOrCtrl: " + dataOrCtrl_qs + "\n" +
                       "FCF: destinationID_id: " + destinationID_qs + "\n" +
                       "FCF: opcode: " + opcode_qs + "\n" +
                       "FCF: senderID: " + senderID_qs + "\n" +
                       "FCF: serialNum " + serialNum_qs);
    mb.setStandardButtons( QMessageBox::Ok| QMessageBox::Cancel);
    mb.setDefaultButton(QMessageBox::Ok);
    int ret = mb.exec();

    //Command line dialog
    print_Status("FCF: dataOrCtrl: " + dataOrCtrl_qs + "\n" +
                 "FCF: destinationID_id: " + destinationID_qs + "\n" +
                 "FCF: opcode: " + opcode_qs + "\n" +
                 "FCF: senderID: " + senderID_qs + "\n" +
                 "FCF: serialNum " + serialNum_qs);

}

void MainWindow::on_value_le_textEdited(QString )

{
    readytoSend();
}

void MainWindow::print_Error(QString print_me)
{
    ui->status_te->setTextColor(QColor(231,47,39,255));
    ui->status_te->append("ERROR: " + print_me);

    debug << "ERROR: " + print_me << endl;
}

void MainWindow::print_Status(QString print_me)
{
    ui->status_te->setTextColor(QColor(0,0,0,100));
    ui->status_te->append("STATUS: " + print_me);

    debug << "STATUS: " + print_me << endl;
}

void MainWindow::loadConfig()
{
    //initializations
    string temp_mname_s;
    int temp_mval_i;
    string temp_pname_s;
    int temp_pval_i;
    QString module_qs;
    int row_count = 0;

    module m1,m2,m3,m4,m5,m6,m7,m8,m9,m10;


    //First thing is first
    //Read in the entire config file and place it in Module structs
    QMap<int,module> mod_map;

    //MODULE1
    if(cfg.lookupValue("M1name",temp_mname_s))
    {
        row_count++;
        cfg.lookupValue("M1val", temp_mval_i);
        m1.name = QString::fromStdString(temp_mname_s);
        m1.value = temp_mval_i;
        m1.active = true;

        if(cfg.lookupValue("P1name1", temp_pname_s))
        {
            cfg.lookupValue("P1val1", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name2", temp_pname_s))
        {
            cfg.lookupValue("P1val2",temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name3", temp_pname_s))
        {
            cfg.lookupValue("P1val3", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name4", temp_pname_s))
        {
            cfg.lookupValue("P1val4", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name5", temp_pname_s))
        {
            cfg.lookupValue("P1val5", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name6", temp_pname_s))
        {
            cfg.lookupValue("P1val6", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name7", temp_pname_s))
        {
            cfg.lookupValue("P1val7", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name8", temp_pname_s))
        {
            cfg.lookupValue("P1val8", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name9", temp_pname_s))
        {
            cfg.lookupValue("P1val9", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P1name10", temp_pname_s))
        {
            cfg.lookupValue("P1val10", temp_pval_i);
            m1.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 1" << endl;
        }
        mod_map.insert(row_count,m1);
        debug << "The first Module from guicomm.cfg" << endl;
        debug << m1.name << "=" << m1.value << endl;

        QMap<QString, int>::const_iterator i = m1.parameters.constBegin();
        while (i != m1.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE2
    if(cfg.lookupValue("M2name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M2val", temp_mval_i);
        m2.name = QString::fromStdString(temp_mname_s);
        m2.value = temp_mval_i;
        m2.active = true;

        if(cfg.lookupValue("P2name1", temp_pname_s))
        {
            cfg.lookupValue("P2val1", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name2", temp_pname_s))
        {
            cfg.lookupValue("P2val2",temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name3", temp_pname_s))
        {
            cfg.lookupValue("P2val3", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name4", temp_pname_s))
        {
            cfg.lookupValue("P2val4", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name5", temp_pname_s))
        {
            cfg.lookupValue("P2val5", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name6", temp_pname_s))
        {
            cfg.lookupValue("P2val6", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name7", temp_pname_s))
        {
            cfg.lookupValue("P2val7", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name8", temp_pname_s))
        {
            cfg.lookupValue("P2val8", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name9", temp_pname_s))
        {
            cfg.lookupValue("P2val9", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P2name10", temp_pname_s))
        {
            cfg.lookupValue("P2val10", temp_pval_i);
            m2.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 2" << endl;
        }
        mod_map.insert(row_count,m2);
        debug << "The second Module from guicomm.cfg" << endl;
        debug << m2.name << "=" << m2.value << endl;

        QMap<QString, int>::const_iterator i = m2.parameters.constBegin();
        while (i != m2.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE3
    if(cfg.lookupValue("M3name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M3val", temp_mval_i);
        m3.name = QString::fromStdString(temp_mname_s);
        m3.value = temp_mval_i;
        m3.active = true;

        if(cfg.lookupValue("P3name1", temp_pname_s))
        {
            cfg.lookupValue("P3val1", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name2", temp_pname_s))
        {
            cfg.lookupValue("P3val2",temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name3", temp_pname_s))
        {
            cfg.lookupValue("P3val3", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name4", temp_pname_s))
        {
            cfg.lookupValue("P3val4", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name5", temp_pname_s))
        {
            cfg.lookupValue("P3val5", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name6", temp_pname_s))
        {
            cfg.lookupValue("P3val6", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name7", temp_pname_s))
        {
            cfg.lookupValue("P3val7", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name8", temp_pname_s))
        {
            cfg.lookupValue("P3val8", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name9", temp_pname_s))
        {
            cfg.lookupValue("P3val9", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P3name10", temp_pname_s))
        {
            cfg.lookupValue("P3val10", temp_pval_i);
            m3.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 3" << endl;
        }
        mod_map.insert(row_count,m3);
        debug << "The third Module from guicomm.cfg" << endl;
        debug << m3.name << "=" << m3.value << endl;

        QMap<QString, int>::const_iterator i = m3.parameters.constBegin();
        while (i != m3.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE4
    if(cfg.lookupValue("M4name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M4val", temp_mval_i);
        m4.name = QString::fromStdString(temp_mname_s);
        m4.value = temp_mval_i;
        m4.active = true;

        if(cfg.lookupValue("P4name1", temp_pname_s))
        {
            cfg.lookupValue("P4val1", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name2", temp_pname_s))
        {
            cfg.lookupValue("P4val2",temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name3", temp_pname_s))
        {
            cfg.lookupValue("P4val3", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name4", temp_pname_s))
        {
            cfg.lookupValue("P4val4", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name5", temp_pname_s))
        {
            cfg.lookupValue("P4val5", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name6", temp_pname_s))
        {
            cfg.lookupValue("P4val6", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name7", temp_pname_s))
        {
            cfg.lookupValue("P4val7", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name8", temp_pname_s))
        {
            cfg.lookupValue("P4val8", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name9", temp_pname_s))
        {
            cfg.lookupValue("P4val9", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P4name70", temp_pname_s))
        {
            cfg.lookupValue("P4val10", temp_pval_i);
            m4.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 4" << endl;
        }
        mod_map.insert(row_count,m4);
        debug << "The fourth Module from guicomm.cfg" << endl;
        debug << m4.name << "=" << m4.value << endl;

        QMap<QString, int>::const_iterator i = m4.parameters.constBegin();
        while (i != m4.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE5
    if(cfg.lookupValue("M5name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M5val", temp_mval_i);
        m5.name = QString::fromStdString(temp_mname_s);
        m5.value = temp_mval_i;
        m5.active = true;

        if(cfg.lookupValue("P5name1", temp_pname_s))
        {
            cfg.lookupValue("P5val1", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name2", temp_pname_s))
        {
            cfg.lookupValue("P5val2",temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name3", temp_pname_s))
        {
            cfg.lookupValue("P5val3", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name4", temp_pname_s))
        {
            cfg.lookupValue("P5val4", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name5", temp_pname_s))
        {
            cfg.lookupValue("P5val5", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name6", temp_pname_s))
        {
            cfg.lookupValue("P5val6", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name7", temp_pname_s))
        {
            cfg.lookupValue("P5val7", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name8", temp_pname_s))
        {
            cfg.lookupValue("P5val8", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name9", temp_pname_s))
        {
            cfg.lookupValue("P5val9", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P5name10", temp_pname_s))
        {
            cfg.lookupValue("P5va10l", temp_pval_i);
            m5.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 5" << endl;
        }
        mod_map.insert(row_count,m5);
        debug << "The fifth Module from guicomm.cfg" << endl;
        debug << m5.name << "=" << m5.value << endl;

        QMap<QString, int>::const_iterator i = m5.parameters.constBegin();
        while (i != m5.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE6
    if(cfg.lookupValue("M6name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M6val", temp_mval_i);
        m6.name = QString::fromStdString(temp_mname_s);
        m6.value = temp_mval_i;
        m6.active = true;

        if(cfg.lookupValue("P6name1", temp_pname_s))
        {
            cfg.lookupValue("P6val1", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name2", temp_pname_s))
        {
            cfg.lookupValue("P6val2",temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name3", temp_pname_s))
        {
            cfg.lookupValue("P6val3", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name4", temp_pname_s))
        {
            cfg.lookupValue("P6val4", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name5", temp_pname_s))
        {
            cfg.lookupValue("P6val5", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name6", temp_pname_s))
        {
            cfg.lookupValue("P6val6", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name7", temp_pname_s))
        {
            cfg.lookupValue("P6val7", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name8", temp_pname_s))
        {
            cfg.lookupValue("P6val8", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name9", temp_pname_s))
        {
            cfg.lookupValue("P6val9", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P6name10", temp_pname_s))
        {
            cfg.lookupValue("P6val10", temp_pval_i);
            m6.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 6" << endl;
        }
        mod_map.insert(row_count,m6);
        debug << "The sixth Module from guicomm.cfg" << endl;
        debug << m6.name << "=" << m6.value << endl;

        QMap<QString, int>::const_iterator i = m6.parameters.constBegin();
        while (i != m6.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE7
    if(cfg.lookupValue("M7name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M7val", temp_mval_i);
        m7.name = QString::fromStdString(temp_mname_s);
        m7.value = temp_mval_i;
        m7.active = true;

        if(cfg.lookupValue("P7name1", temp_pname_s))
        {
            cfg.lookupValue("P7val1", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name2", temp_pname_s))
        {
            cfg.lookupValue("P7val2",temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name3", temp_pname_s))
        {
            cfg.lookupValue("P7val3", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name4", temp_pname_s))
        {
            cfg.lookupValue("P7val4", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name5", temp_pname_s))
        {
            cfg.lookupValue("P7val5", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name6", temp_pname_s))
        {
            cfg.lookupValue("P7val6", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name7", temp_pname_s))
        {
            cfg.lookupValue("P7val7", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name8", temp_pname_s))
        {
            cfg.lookupValue("P7val8", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name9", temp_pname_s))
        {
            cfg.lookupValue("P7val9", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P7name10", temp_pname_s))
        {
            cfg.lookupValue("P7val10", temp_pval_i);
            m7.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 7" << endl;
        }
        mod_map.insert(row_count,m7);
        debug << "The seventh Module from guicomm.cfg" << endl;
        debug << m7.name << "=" << m7.value << endl;

        QMap<QString, int>::const_iterator i = m7.parameters.constBegin();
        while (i != m7.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE8
    if(cfg.lookupValue("M8name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M8val", temp_mval_i);
        m8.name = QString::fromStdString(temp_mname_s);
        m8.value = temp_mval_i;
        m8.active = true;

        if(cfg.lookupValue("P8name1", temp_pname_s))
        {
            cfg.lookupValue("P8val1", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name2", temp_pname_s))
        {
            cfg.lookupValue("P8val2",temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name3", temp_pname_s))
        {
            cfg.lookupValue("P8val3", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name4", temp_pname_s))
        {
            cfg.lookupValue("P8val4", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name5", temp_pname_s))
        {
            cfg.lookupValue("P8val5", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name6", temp_pname_s))
        {
            cfg.lookupValue("P8val6", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name7", temp_pname_s))
        {
            cfg.lookupValue("P8val7", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name8", temp_pname_s))
        {
            cfg.lookupValue("P8val8", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name9", temp_pname_s))
        {
            cfg.lookupValue("P8val9", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P8name10", temp_pname_s))
        {
            cfg.lookupValue("P8val10", temp_pval_i);
            m8.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 8" << endl;
        }
        mod_map.insert(row_count,m8);
        debug << "The eigth Module from guicomm.cfg" << endl;
        debug << m8.name << "=" << m8.value << endl;

        QMap<QString, int>::const_iterator i = m8.parameters.constBegin();
        while (i != m8.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE9
    if(cfg.lookupValue("M9name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M9val", temp_mval_i);
        m9.name = QString::fromStdString(temp_mname_s);
        m9.value = temp_mval_i;
        m9.active = true;

        if(cfg.lookupValue("P9name1", temp_pname_s))
        {
            cfg.lookupValue("P9val1", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name2", temp_pname_s))
        {
            cfg.lookupValue("P9val2",temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name3", temp_pname_s))
        {
            cfg.lookupValue("P9val3", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name4", temp_pname_s))
        {
            cfg.lookupValue("P9val4", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name5", temp_pname_s))
        {
            cfg.lookupValue("P9val5", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name6", temp_pname_s))
        {
            cfg.lookupValue("P9val6", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name7", temp_pname_s))
        {
            cfg.lookupValue("P9val7", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name8", temp_pname_s))
        {
            cfg.lookupValue("P9val8", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name9", temp_pname_s))
        {
            cfg.lookupValue("P9val9", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P9name10", temp_pname_s))
        {
            cfg.lookupValue("P9val10", temp_pval_i);
            m9.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 9" << endl;
        }
        mod_map.insert(row_count,m9);
        debug << "The nineth Module from guicomm.cfg" << endl;
        debug << m9.name << "=" << m9.value << endl;

        QMap<QString, int>::const_iterator i = m9.parameters.constBegin();
        while (i != m9.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }

    //MODULE10
    if(cfg.lookupValue("M10name",temp_mname_s))
    {

        row_count++;
        cfg.lookupValue("M10val", temp_mval_i);
        m10.name = QString::fromStdString(temp_mname_s);
        m10.value = temp_mval_i;
        m10.active = true;

        if(cfg.lookupValue("P10name1", temp_pname_s))
        {
            cfg.lookupValue("P10val1", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name2", temp_pname_s))
        {
            cfg.lookupValue("P10val2",temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name3", temp_pname_s))
        {
            cfg.lookupValue("P10val3", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name4", temp_pname_s))
        {
            cfg.lookupValue("P10val4", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name5", temp_pname_s))
        {
            cfg.lookupValue("P10val5", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name6", temp_pname_s))
        {
            cfg.lookupValue("P10val6", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name7", temp_pname_s))
        {
            cfg.lookupValue("P10val7", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name8", temp_pname_s))
        {
            cfg.lookupValue("P10val8", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name9", temp_pname_s))
        {
            cfg.lookupValue("P10val9", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        if(cfg.lookupValue("P10name10", temp_pname_s))
        {
            cfg.lookupValue("P10val10", temp_pval_i);
            m10.parameters.insert(QString::fromStdString(temp_pname_s),temp_pval_i);
        }
        else
        {
            debug << "The configuration file does not contain properly formatted parameters for Module 10" << endl;
        }
        mod_map.insert(row_count,m10);
        debug << "The tenth Module from guicomm.cfg" << endl;
        debug << m10.name << "=" << m10.value << endl;

        QMap<QString, int>::const_iterator i = m10.parameters.constBegin();
        while (i != m10.parameters.constEnd())
        {
            debug << i.key() << ": " << i.value() << endl;
            ++i;
        }
    }



    //FILL IN THE GUI

    //TODO
    //  Create a table widget for each module
    //  Put name of module as the first row
    //  Fill in each parameter in the format you drew in the notebook

    //Look into chaning from MainWindow to a Widget based class.

    if(m1.active)
    {
        QTableWidget m1_tw = new QTableWidget(ui);
        QTableWidgetItem m1_twi;
        m1_twi.setText(m1.name);
        m1_tw.setItem(1,1,&m1_twi);

        QApplication::translate();
    }

}
