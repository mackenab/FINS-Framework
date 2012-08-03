/********************************************************************************
** Form generated from reading UI file 'guicomm_mw.ui'
**
** Created: Mon Aug 1 10:46:59 2011
**      by: Qt User Interface Compiler version 4.6.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_GUICOMM_MW_H
#define UI_GUICOMM_MW_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QComboBox>
#include <QtGui/QGridLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QTableWidget>
#include <QtGui/QTextEdit>
#include <QtGui/QToolBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *actionQuit;
    QWidget *centralWidget;
    QWidget *gridLayoutWidget;
    QGridLayout *gridLayout;
    QLabel *module_l;
    QComboBox *module_cb;
    QComboBox *param_cb;
    QLabel *parameter_l;
    QLabel *value_l;
    QLineEdit *value_le;
    QPushButton *setparam_pb;
    QLabel *operation_l;
    QComboBox *operation_cb;
    QLabel *interval_l;
    QLineEdit *interval_le;
    QTextEdit *realtime_te;
    QLabel *realtime_l;
    QTableWidget *overtime_tw;
    QLabel *overtime_l;
    QMenuBar *menuBar;
    QMenu *menuFile;
    QToolBar *mainToolBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(748, 459);
        MainWindow->setMinimumSize(QSize(0, 0));
        actionQuit = new QAction(MainWindow);
        actionQuit->setObjectName(QString::fromUtf8("actionQuit"));
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        centralWidget->setMaximumSize(QSize(16777215, 16777215));
        centralWidget->setLayoutDirection(Qt::LeftToRight);
        gridLayoutWidget = new QWidget(centralWidget);
        gridLayoutWidget->setObjectName(QString::fromUtf8("gridLayoutWidget"));
        gridLayoutWidget->setGeometry(QRect(10, 0, 711, 151));
        gridLayoutWidget->setMinimumSize(QSize(2, 0));
        gridLayout = new QGridLayout(gridLayoutWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        gridLayout->setSizeConstraint(QLayout::SetDefaultConstraint);
        gridLayout->setContentsMargins(0, 0, 0, 0);
        module_l = new QLabel(gridLayoutWidget);
        module_l->setObjectName(QString::fromUtf8("module_l"));
        module_l->setMinimumSize(QSize(2, 0));
        module_l->setAlignment(Qt::AlignBottom|Qt::AlignLeading|Qt::AlignLeft);

        gridLayout->addWidget(module_l, 0, 0, 1, 1);

        module_cb = new QComboBox(gridLayoutWidget);
        module_cb->setObjectName(QString::fromUtf8("module_cb"));
        module_cb->setMinimumSize(QSize(2, 0));

        gridLayout->addWidget(module_cb, 1, 0, 1, 1);

        param_cb = new QComboBox(gridLayoutWidget);
        param_cb->setObjectName(QString::fromUtf8("param_cb"));
        param_cb->setMinimumSize(QSize(2, 0));

        gridLayout->addWidget(param_cb, 1, 1, 1, 1);

        parameter_l = new QLabel(gridLayoutWidget);
        parameter_l->setObjectName(QString::fromUtf8("parameter_l"));
        parameter_l->setMinimumSize(QSize(2, 0));
        parameter_l->setAlignment(Qt::AlignBottom|Qt::AlignLeading|Qt::AlignLeft);

        gridLayout->addWidget(parameter_l, 0, 1, 1, 1);

        value_l = new QLabel(gridLayoutWidget);
        value_l->setObjectName(QString::fromUtf8("value_l"));
        value_l->setMinimumSize(QSize(2, 0));
        value_l->setAlignment(Qt::AlignBottom|Qt::AlignLeading|Qt::AlignLeft);

        gridLayout->addWidget(value_l, 0, 4, 1, 1);

        value_le = new QLineEdit(gridLayoutWidget);
        value_le->setObjectName(QString::fromUtf8("value_le"));
        value_le->setMinimumSize(QSize(2, 0));

        gridLayout->addWidget(value_le, 1, 4, 1, 1);

        setparam_pb = new QPushButton(gridLayoutWidget);
        setparam_pb->setObjectName(QString::fromUtf8("setparam_pb"));
        setparam_pb->setMinimumSize(QSize(2, 0));

        gridLayout->addWidget(setparam_pb, 2, 4, 1, 1);

        operation_l = new QLabel(gridLayoutWidget);
        operation_l->setObjectName(QString::fromUtf8("operation_l"));
        operation_l->setMinimumSize(QSize(2, 0));
        operation_l->setAlignment(Qt::AlignBottom|Qt::AlignLeading|Qt::AlignLeft);

        gridLayout->addWidget(operation_l, 0, 2, 1, 1);

        operation_cb = new QComboBox(gridLayoutWidget);
        operation_cb->setObjectName(QString::fromUtf8("operation_cb"));
        operation_cb->setMinimumSize(QSize(2, 0));

        gridLayout->addWidget(operation_cb, 1, 2, 1, 1);

        interval_l = new QLabel(gridLayoutWidget);
        interval_l->setObjectName(QString::fromUtf8("interval_l"));
        interval_l->setMinimumSize(QSize(2, 0));
        interval_l->setLineWidth(1);
        interval_l->setAlignment(Qt::AlignBottom|Qt::AlignLeading|Qt::AlignLeft);

        gridLayout->addWidget(interval_l, 0, 3, 1, 1);

        interval_le = new QLineEdit(gridLayoutWidget);
        interval_le->setObjectName(QString::fromUtf8("interval_le"));
        interval_le->setMinimumSize(QSize(2, 0));

        gridLayout->addWidget(interval_le, 1, 3, 1, 1);

        realtime_te = new QTextEdit(centralWidget);
        realtime_te->setObjectName(QString::fromUtf8("realtime_te"));
        realtime_te->setGeometry(QRect(10, 180, 711, 21));
        realtime_te->setMinimumSize(QSize(2, 0));
        realtime_l = new QLabel(centralWidget);
        realtime_l->setObjectName(QString::fromUtf8("realtime_l"));
        realtime_l->setGeometry(QRect(10, 160, 62, 17));
        realtime_l->setMinimumSize(QSize(2, 0));
        overtime_tw = new QTableWidget(centralWidget);
        overtime_tw->setObjectName(QString::fromUtf8("overtime_tw"));
        overtime_tw->setGeometry(QRect(10, 230, 711, 171));
        overtime_l = new QLabel(centralWidget);
        overtime_l->setObjectName(QString::fromUtf8("overtime_l"));
        overtime_l->setGeometry(QRect(10, 210, 62, 17));
        overtime_l->setMinimumSize(QSize(2, 0));
        MainWindow->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 748, 23));
        menuFile = new QMenu(menuBar);
        menuFile->setObjectName(QString::fromUtf8("menuFile"));
        MainWindow->setMenuBar(menuBar);
        mainToolBar = new QToolBar(MainWindow);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        MainWindow->addToolBar(Qt::TopToolBarArea, mainToolBar);

        menuBar->addAction(menuFile->menuAction());
        menuFile->addAction(actionQuit);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "MainWindow", 0, QApplication::UnicodeUTF8));
        actionQuit->setText(QApplication::translate("MainWindow", "Quit", 0, QApplication::UnicodeUTF8));
        module_l->setText(QApplication::translate("MainWindow", "Module", 0, QApplication::UnicodeUTF8));
        module_cb->clear();
        module_cb->insertItems(0, QStringList()
         << QApplication::translate("MainWindow", "<Select>", 0, QApplication::UnicodeUTF8)
        );
        param_cb->clear();
        param_cb->insertItems(0, QStringList()
         << QApplication::translate("MainWindow", "Empty", 0, QApplication::UnicodeUTF8)
        );
        parameter_l->setText(QApplication::translate("MainWindow", "Parameter", 0, QApplication::UnicodeUTF8));
        value_l->setText(QApplication::translate("MainWindow", "Value", 0, QApplication::UnicodeUTF8));
        setparam_pb->setText(QApplication::translate("MainWindow", "Set Parameter", 0, QApplication::UnicodeUTF8));
        operation_l->setText(QApplication::translate("MainWindow", "Operation", 0, QApplication::UnicodeUTF8));
        operation_cb->clear();
        operation_cb->insertItems(0, QStringList()
         << QApplication::translate("MainWindow", "<Select>", 0, QApplication::UnicodeUTF8)
         << QApplication::translate("MainWindow", "Set Parameter", 0, QApplication::UnicodeUTF8)
         << QApplication::translate("MainWindow", "Read Parameter Real Time", 0, QApplication::UnicodeUTF8)
         << QApplication::translate("MainWindow", "Read Parameter Over Time", 0, QApplication::UnicodeUTF8)
        );
        interval_l->setText(QApplication::translate("MainWindow", "Logging Interval", 0, QApplication::UnicodeUTF8));
        interval_le->setText(QApplication::translate("MainWindow", "5", 0, QApplication::UnicodeUTF8));
        realtime_l->setText(QApplication::translate("MainWindow", "Realtime", 0, QApplication::UnicodeUTF8));
        overtime_l->setText(QApplication::translate("MainWindow", "Overtime", 0, QApplication::UnicodeUTF8));
        menuFile->setTitle(QApplication::translate("MainWindow", "File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_GUICOMM_MW_H
