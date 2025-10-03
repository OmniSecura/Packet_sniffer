/****************************************************************************
** Meta object code from reading C++ file 'geooverviewdialog.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.8.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "src/statistics/geooverviewdialog.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'geooverviewdialog.h' doesn't include <QObject>."
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
struct qt_meta_tag_ZN17GeoOverviewDialogE_t {};
} // unnamed namespace


#ifdef QT_MOC_HAS_STRINGDATA
static constexpr auto qt_meta_stringdata_ZN17GeoOverviewDialogE = QtMocHelpers::stringData(
    "GeoOverviewDialog",
    "onSliderValueChanged",
    "",
    "value",
    "onEventSelectionChanged",
    "row",
    "togglePlayback",
    "playNext",
    "playPrevious",
    "handleFlightFinished",
    "performSearch",
    "handleStartFilterToggled",
    "checked",
    "handleEndFilterToggled",
    "populateIpDropdown",
    "syncIpDropdownSelection",
    "ip"
);
#else  // !QT_MOC_HAS_STRINGDATA
#error "qtmochelpers.h not found or too old."
#endif // !QT_MOC_HAS_STRINGDATA

Q_CONSTINIT static const uint qt_meta_data_ZN17GeoOverviewDialogE[] = {

 // content:
      12,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   80,    2, 0x08,    1 /* Private */,
       4,    1,   83,    2, 0x08,    3 /* Private */,
       6,    0,   86,    2, 0x08,    5 /* Private */,
       7,    0,   87,    2, 0x08,    6 /* Private */,
       8,    0,   88,    2, 0x08,    7 /* Private */,
       9,    0,   89,    2, 0x08,    8 /* Private */,
      10,    0,   90,    2, 0x08,    9 /* Private */,
      11,    1,   91,    2, 0x08,   10 /* Private */,
      13,    1,   94,    2, 0x08,   12 /* Private */,
      14,    0,   97,    2, 0x08,   14 /* Private */,
      15,    1,   98,    2, 0x08,   15 /* Private */,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    5,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   12,
    QMetaType::Void, QMetaType::Bool,   12,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   16,

       0        // eod
};

Q_CONSTINIT const QMetaObject GeoOverviewDialog::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_ZN17GeoOverviewDialogE.offsetsAndSizes,
    qt_meta_data_ZN17GeoOverviewDialogE,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_tag_ZN17GeoOverviewDialogE_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<GeoOverviewDialog, std::true_type>,
        // method 'onSliderValueChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'onEventSelectionChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'togglePlayback'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'playNext'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'playPrevious'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'handleFlightFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'performSearch'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'handleStartFilterToggled'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        // method 'handleEndFilterToggled'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        // method 'populateIpDropdown'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'syncIpDropdownSelection'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>
    >,
    nullptr
} };

void GeoOverviewDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<GeoOverviewDialog *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->onSliderValueChanged((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 1: _t->onEventSelectionChanged((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 2: _t->togglePlayback(); break;
        case 3: _t->playNext(); break;
        case 4: _t->playPrevious(); break;
        case 5: _t->handleFlightFinished(); break;
        case 6: _t->performSearch(); break;
        case 7: _t->handleStartFilterToggled((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1]))); break;
        case 8: _t->handleEndFilterToggled((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1]))); break;
        case 9: _t->populateIpDropdown(); break;
        case 10: _t->syncIpDropdownSelection((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        default: ;
        }
    }
}

const QMetaObject *GeoOverviewDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *GeoOverviewDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ZN17GeoOverviewDialogE.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int GeoOverviewDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 11)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 11;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 11)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 11;
    }
    return _id;
}
QT_WARNING_POP
