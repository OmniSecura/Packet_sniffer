#ifndef SELECTIONANNOTATIONDIALOG_H
#define SELECTIONANNOTATIONDIALOG_H

#include <QColor>
#include <QDialog>
#include <QString>
#include <QStringList>
#include <QVector>

class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTextEdit;

class SelectionAnnotationDialog : public QDialog
{
    Q_OBJECT
public:
    struct Result {
        QString title;
        QString description;
        QStringList tags;
        QString threatLevel;
        QString recommendedAction;
        QColor color;
    };

    explicit SelectionAnnotationDialog(const QVector<int> &rows, QWidget *parent = nullptr);

    Result result() const;

private slots:
    void chooseColor();

private:
    void updateColorPreview();
    QString defaultTagForThreat() const;

    QVector<int> m_rows;
    QColor m_color;

    QLabel *m_summaryLabel;
    QLineEdit *m_titleEdit;
    QTextEdit *m_descriptionEdit;
    QComboBox *m_threatCombo;
    QLineEdit *m_tagsEdit;
    QComboBox *m_actionCombo;
    QPushButton *m_colorButton;
    QDialogButtonBox *m_buttonBox;
};

#endif // SELECTIONANNOTATIONDIALOG_H
