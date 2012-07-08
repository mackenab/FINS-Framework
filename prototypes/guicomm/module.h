#ifndef MODULE_H
#define MODULE_H

#include <QMap>
#include <QString>

struct module
{
    bool active;    //whether or not the module is defined in the config file
    QString name;   //name of the module (ex: UDP)
    int value;
    QMap<QString,int> parameters;   //all the corresponding parameters
};

#endif // MODULE_H
