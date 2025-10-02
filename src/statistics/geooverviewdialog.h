#ifndef GEOOVERVIEWDIALOG_H
#define GEOOVERVIEWDIALOG_H

#include <QDialog>
#include <QVector>
#include <QStringList>
#include <limits>

class PacketTableModel;
class GeoMapWidget;
class GeoLocation;
class QListWidget;
class QSlider;
class QPushButton;
class QLabel;

class GeoOverviewDialog : public QDialog {
    Q_OBJECT
public:
    GeoOverviewDialog(PacketTableModel *model, GeoLocation *geo, QWidget *parent = nullptr);

private slots:
    void onSliderValueChanged(int value);
    void onEventSelectionChanged(int row);
    void togglePlayback();
    void playNext();
    void playPrevious();
    void handleFlightFinished();

private:
    struct FlightEvent {
        int packetNumber = 0;
        double timeSeconds = 0.0;
        QString timeStamp;
        QString srcIp;
        QString dstIp;
        QString protocol;
        QString length;
        QString info;
        QString srcCountry;
        QString dstCountry;
        QStringList isoCodes;
        double srcLat = std::numeric_limits<double>::quiet_NaN();
        double srcLon = std::numeric_limits<double>::quiet_NaN();
        double dstLat = std::numeric_limits<double>::quiet_NaN();
        double dstLon = std::numeric_limits<double>::quiet_NaN();
        bool hasCoordinates = false;
    };

    void buildEvents(PacketTableModel *model, GeoLocation *geo);
    void setCurrentEvent(int index, bool userInitiated);
    void updateMapForEvent(const FlightEvent &event);
    void updateControlsState();

    GeoMapWidget *m_map = nullptr;
    QListWidget *m_eventList = nullptr;
    QSlider *m_slider = nullptr;
    QPushButton *m_playButton = nullptr;
    QPushButton *m_nextButton = nullptr;
    QPushButton *m_prevButton = nullptr;
    QLabel *m_infoLabel = nullptr;
    QLabel *m_detailLabel = nullptr;

    QVector<FlightEvent> m_events;
    int m_currentIndex = -1;
    bool m_isPlaying = false;
};

#endif // GEOOVERVIEWDIALOG_H
