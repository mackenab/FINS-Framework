/****************************************************************************
** Meta object code from reading C++ file 'guicomm_mw.h'
**
** Created: Mon Aug 1 10:47:02 2011
**      by: The Qt Meta Object Compiler version 62 (Qt 4.6.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "guicomm_mw.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'guicomm_mw.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 62
#error "This file was generated using the moc from 4.6.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_MainWindow[] = {

 // content:
       4,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      12,   11,   11,   11, 0x08,
      44,   11,   11,   11, 0x08,
      70,   11,   11,   11, 0x08,
     105,   11,   11,   11, 0x08,
     136,   11,   11,   11, 0x08,
     161,   11,   11,   11, 0x08,

       0        // eod
};

static const char qt_meta_stringdata_MainWindow[] = {
    "MainWindow\0\0on_value_le_textEdited(QString)\0"
    "on_actionQuit_triggered()\0"
    "on_operation_cb_activated(QString)\0"
    "on_param_cb_activated(QString)\0"
    "on_setparam_pb_clicked()\0"
    "on_module_cb_activated(QString)\0"
};

const QMetaObject MainWindow::staticMetaObject = {
    { &QMainWindow::staticMetaObject, qt_meta_stringdata_MainWindow,
      qt_meta_data_MainWindow, 0 }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &MainWindow::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *MainWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *MainWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_MainWindow))
        return static_cast<void*>(const_cast< MainWindow*>(this));
    return QMainWindow::qt_metacast(_clname);
}

int MainWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: on_value_le_textEdited((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 1: on_actionQuit_triggered(); break;
        case 2: on_operation_cb_activated((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 3: on_param_cb_activated((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 4: on_setparam_pb_clicked(); break;
        case 5: on_module_cb_activated((*reinterpret_cast< QString(*)>(_a[1]))); break;
        default: ;
        }
        _id -= 6;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
