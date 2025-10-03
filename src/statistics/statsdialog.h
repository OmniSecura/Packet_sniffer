#ifndef STATSDIALOG_H
#define STATSDIALOG_H

#include "charts/barchart.h"
#include "charts/linechart.h"
#include "charts/ChartConfig.h"
#include <QtGlobal>

class FlowTableModel;
class QTableView;
class QPushButton;
class QComboBox;

class StatsDialog : public QDialog {
    Q_OBJECT

public:
    explicit StatsDialog(QWidget *parent = nullptr);
    ~StatsDialog();

    void updateOptionsBar(int index);

signals:
    void flowSelected(const QString &protocol,
                      const QString &srcAddr,
                      quint16 srcPort,
                      const QString &dstAddr,
                      quint16 dstPort);
    void flowSelectionCleared();

private:
    QHBoxLayout    *optionsBar;
    QStackedWidget *stackedWidget;

    QPushButton *barChartBtn, *lineChartBtn, *flowBtn, *protocolBtn;
    QComboBox   *barFilter   = nullptr;
    QComboBox   *sessionSel  = nullptr;
    QComboBox   *sortCombo   = nullptr;

    // LineChart controls
    QComboBox   *lineMode    = nullptr;
    QComboBox   *lineSession = nullptr;
    QComboBox   *metricCombo = nullptr;

    // Flow table controls
    QComboBox   *flowMode    = nullptr;
    QComboBox   *flowSession = nullptr;
    QPushButton *clearFlowButton = nullptr;

    QScrollArea *barScrollArea;
    BarChart    *barChartWidget;
    LineChart   *lineChartWidget;
    FlowTableModel *flowModel;
    QTableView     *flowTableView;
};

#endif // STATSDIALOG_H
