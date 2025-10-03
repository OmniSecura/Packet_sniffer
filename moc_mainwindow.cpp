/****************************************************************************
** Meta object code from reading C++ file 'mainwindow.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.8.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "src/mainwindow.h"
#include <QtGui/qtextcursor.h>
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'mainwindow.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.8.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN10MainWindowE_t {};
} // unnamed namespace


#ifdef QT_MOC_HAS_STRINGDATA
static constexpr auto qt_meta_stringdata_ZN10MainWindowE = QtMocHelpers::stringData(
    "MainWindow",
    "startSniffing",
    "",
    "stopSniffing",
    "handlePacket",
    "raw",
    "infos",
    "linkType",
    "onPacketClicked",
    "QModelIndex",
    "index",
    "showColorizeCustomizer",
    "startNewSession",
    "onPacketTableContextMenu",
    "pos",
    "onFilterTextChanged",
    "text",
    "toggleTheme",
    "updateSessionTime",
    "updateProtocolCombo",
    "showOtherThemesDialog",
    "openPreferences",
    "openSessionManager"
);
#else  // !QT_MOC_HAS_STRINGDATA
#error "qtmochelpers.h not found or too old."
#endif // !QT_MOC_HAS_STRINGDATA

Q_CONSTINIT static const uint qt_meta_data_ZN10MainWindowE[] = {

 // content:
      12,       // revision
       0,       // classname
       0,    0, // classinfo
      14,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   98,    2, 0x08,    1 /* Private */,
       3,    0,   99,    2, 0x08,    2 /* Private */,
       4,    3,  100,    2, 0x08,    3 /* Private */,
       8,    1,  107,    2, 0x08,    7 /* Private */,
      11,    0,  110,    2, 0x08,    9 /* Private */,
      12,    0,  111,    2, 0x08,   10 /* Private */,
      13,    1,  112,    2, 0x08,   11 /* Private */,
      15,    1,  115,    2, 0x08,   13 /* Private */,
      17,    0,  118,    2, 0x08,   15 /* Private */,
      18,    0,  119,    2, 0x08,   16 /* Private */,
      19,    0,  120,    2, 0x08,   17 /* Private */,
      20,    0,  121,    2, 0x08,   18 /* Private */,
      21,    0,  122,    2, 0x08,   19 /* Private */,
      22,    0,  123,    2, 0x08,   20 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QByteArray, QMetaType::QStringList, QMetaType::Int,    5,    6,    7,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QPoint,   14,
    QMetaType::Void, QMetaType::QString,   16,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject MainWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_ZN10MainWindowE.offsetsAndSizes,
    qt_meta_data_ZN10MainWindowE,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_tag_ZN10MainWindowE_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<MainWindow, std::true_type>,
        // method 'startSniffing'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'stopSniffing'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'handlePacket'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QByteArray &, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QStringList &, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'onPacketClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QModelIndex &, std::false_type>,
        // method 'showColorizeCustomizer'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'startNewSession'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onPacketTableContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QPoint &, std::false_type>,
        // method 'onFilterTextChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'toggleTheme'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'updateSessionTime'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'updateProtocolCombo'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'showOtherThemesDialog'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'openPreferences'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'openSessionManager'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void MainWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<MainWindow *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->startSniffing(); break;
        case 1: _t->stopSniffing(); break;
        case 2: _t->handlePacket((*reinterpret_cast< std::add_pointer_t<QByteArray>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QStringList>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[3]))); break;
        case 3: _t->onPacketClicked((*reinterpret_cast< std::add_pointer_t<QModelIndex>>(_a[1]))); break;
        case 4: _t->showColorizeCustomizer(); break;
        case 5: _t->startNewSession(); break;
        case 6: _t->onPacketTableContextMenu((*reinterpret_cast< std::add_pointer_t<QPoint>>(_a[1]))); break;
        case 7: _t->onFilterTextChanged((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 8: _t->toggleTheme(); break;
        case 9: _t->updateSessionTime(); break;
        case 10: _t->updateProtocolCombo(); break;
        case 11: _t->showOtherThemesDialog(); break;
        case 12: _t->openPreferences(); break;
        case 13: _t->openSessionManager(); break;
        default: ;
        }
    }
}

const QMetaObject *MainWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MainWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ZN10MainWindowE.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int MainWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 14)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 14;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 14)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 14;
    }
    return _id;
}
QT_WARNING_POP
