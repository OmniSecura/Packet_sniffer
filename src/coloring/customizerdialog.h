#ifndef CUSTOMIZERDIALOG_H
#define CUSTOMIZERDIALOG_H
#include <QDialog>
#include <QVector>
#include "coloringrule.h"
#include <QDialogButtonBox>
#include <QListWidget>
#include <QPushButton>
#include <QColorDialog>
#include <QInputDialog>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <pcap.h>

class QListWidget;
class QPushButton;

class CustomizerDialog : public QDialog {
    Q_OBJECT

public:
    explicit CustomizerDialog(QWidget *parent,
                              QVector<ColoringRule> initialRules);
    ~CustomizerDialog() override;

    QVector<ColoringRule> takeRules();

private slots:
    void onAdd();
    void onEdit();
    void onRemove();

private:
    void rebuildList();

    QVector<ColoringRule> m_rules;
    QListWidget*          m_listWidget;
    QPushButton*          m_addBtn;
    QPushButton*          m_editBtn;
    QPushButton*          m_removeBtn;
};

#endif // CUSTOMIZERDIALOG_H
