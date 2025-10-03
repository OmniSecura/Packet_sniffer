
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QComboBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableView>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QTabWidget>
#include <QThread>
#include <QTreeWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QMenuBar>
#include <QApplication>
#include <QFileDialog>
#include <QPoint>
#include <QAction>
#include <QMenu>
#include <QStatusBar>
#include <QLabel>
#include <QTimer>
#include <QMap>
#include <QDateTime>
#include <QVector>
#include <QStringList>
#include <memory>
#include <arpa/inet.h>
#include <pcap.h>
#include "packetworker.h"
#include "packets/sniffing.h"
#include "coloring/packetcolorizer.h"
#include "theme/theme.h"
#include "theme/otherthemesdialog.h"
#include "coloring/customizerdialog.h"
#include "../packets/packethelpers.h"
#include "statistics/statsdialog.h"
#include "statistics/statistics.h"
#include "statistics/sessionstorage.h"
#include "statistics/charts/pieChart.h"
#include "packets/packet_geolocation/geolocation.h"
#include "packets/packet_geolocation/GeoMap.h"
#include "packets/packet_geolocation/CountryMapping/CountryMap.h"
#include "PacketTableModel.h"
#include "appsettings.h"

struct PacketAnnotationItem {
    int row = -1;
    QStringList tags;
    QColor color;
};

struct PacketAnnotation {
    QString title;
    QString description;
    QStringList tags;
    QString threatLevel;
    QString recommendedAction;
    QVector<PacketAnnotationItem> packets;
    QDateTime createdAt;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void startSniffing();
    void stopSniffing();
    void handlePacket(const QByteArray &raw, const QStringList &infos, int linkType);
    // void onPacketClicked(int row, int col);
    void onPacketClicked(const QModelIndex &index);
    void showColorizeCustomizer();
    void startNewSession();
    void onPacketTableContextMenu(const QPoint &pos);
    void onFilterTextChanged(const QString &text);
    void toggleTheme();
    void updateSessionTime();
    void updateProtocolCombo();
    void showOtherThemesDialog();
    void openPreferences();
    void openSessionManager();
    void togglePayloadOnlyMode(bool enabled);
    void onPayloadDecodeChanged(int index);
    void openFollowStreamDialog();

private:
    void setupUI();
    void listInterfaces();
    QStringList infoColumn(const QStringList &summary, const u_char *pkt, int linkType);
    void addLayerToTree(QTreeWidget *tree, const PacketLayer &lay);
    void saveAnnotationToFile(const PacketAnnotation &annotation);
    void loadPreferences();
    void persistCurrentSession();
    bool loadOfflineSession(const SessionStorage::LoadedSession &session);

    PacketColorizer packetColorizer;

    QComboBox   *ifaceBox;
    QLineEdit   *filterEdit;
    QCheckBox   *promiscBox;
    QPushButton *startBtn;
    QPushButton *stopBtn;

    // QTableWidget *packetTable; //QTableWidget before QTableView
    QSplitter    *mainSplitter;
    QSplitter    *leftSplitter;
    QSplitter    *rightSplitter;
    QTableView   *packetTable;
    PacketTableModel *packetModel;
    QTreeWidget  *detailsTree;
    QTabWidget   *payloadTabs;
    QPlainTextEdit *hexEdit;
    QPlainTextEdit *payloadView;
    QComboBox    *payloadDecodeCombo;

    QThread      *workerThread;
    PacketWorker *worker;
    Sniffing      parser;

    QAction *actionOpen = nullptr;
    QAction *actionSave = nullptr;
    QAction *newSession = nullptr;
    QAction  *themeToggleAction;
    QAction *otherThemesAction;
    QAction *showPayloadOnlyAction = nullptr;

    // --- Status bar widgets ---
    QLabel   *packetCountLabel;
    QLabel   *sessionTimeLabel;
    QTimer   *sessionTimer;
    QDateTime sessionStartTime;
    qint64    packetCount;
    QComboBox          *protocolCombo;
    QMap<QString,int>   protocolCounts;

    //charts
    PieChart     *pieChart;
    std::unique_ptr<Statistics> stats;
    QTimer *statsTimer = nullptr;

    //geolocation
    GeoLocation geo;
    GeoMapWidget *mapWidget = nullptr;

    QVector<PacketAnnotation> annotations;

    QByteArray currentPayload;
    bool payloadOnlyMode = false;

    AppSettings appSettings;

    void updatePayloadView();
    void applyPayloadOnlyMode(bool enabled);
};

#endif // MAINWINDOW_H
