#include "geooverviewdialog.h"

#include "../PacketTableModel.h"
#include "../../packets/packet_geolocation/GeoMap.h"
#include "../../packets/packet_geolocation/geolocation.h"
#include "../../packets/packet_geolocation/CountryMapping/CountryMap.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QSlider>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>
#include <QSignalBlocker>
#include <QAbstractItemView>
#include <QCoreApplication>
#include <QLocale>
#include <QTimer>

#include <cmath>

namespace {
QString formatCountryLabel(const QString &country, const QString &fallback)
{
    if (!country.trimmed().isEmpty())
        return country;
    return fallback;
}
}

GeoOverviewDialog::GeoOverviewDialog(PacketTableModel *model,
                                     GeoLocation *geo,
                                     QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("GeoOverview"));
    resize(1000, 680);

    auto *mainLayout = new QVBoxLayout(this);

    const QString mapPath = QCoreApplication::applicationDirPath() + "/resources/WorldMap.svg";
    m_map = new GeoMapWidget(mapPath, this);
    m_map->setMinimumHeight(360);

    connect(m_map, &GeoMapWidget::flightAnimationFinished,
            this, &GeoOverviewDialog::handleFlightFinished);

    auto *splitter = new QSplitter(Qt::Vertical);
    splitter->addWidget(m_map);

    QWidget *lowerPanel = new QWidget;
    auto *lowerLayout = new QVBoxLayout(lowerPanel);
    lowerLayout->setContentsMargins(0, 0, 0, 0);

    auto *controlsLayout = new QHBoxLayout;
    m_prevButton = new QPushButton(tr("⏮"));
    m_playButton = new QPushButton(tr("Play"));
    m_nextButton = new QPushButton(tr("⏭"));
    m_slider = new QSlider(Qt::Horizontal);

    m_prevButton->setToolTip(tr("Previous packet"));
    m_nextButton->setToolTip(tr("Next packet"));
    m_playButton->setToolTip(tr("Play / Pause"));

    controlsLayout->addWidget(m_prevButton);
    controlsLayout->addWidget(m_playButton);
    controlsLayout->addWidget(m_nextButton);
    controlsLayout->addWidget(m_slider, 1);

    lowerLayout->addLayout(controlsLayout);

    m_infoLabel = new QLabel;
    m_infoLabel->setWordWrap(true);
    m_detailLabel = new QLabel;
    m_detailLabel->setWordWrap(true);
    m_detailLabel->setStyleSheet("color: palette(mid);");

    lowerLayout->addWidget(m_infoLabel);
    lowerLayout->addWidget(m_detailLabel);

    m_eventList = new QListWidget;
    m_eventList->setSelectionMode(QAbstractItemView::SingleSelection);
    lowerLayout->addWidget(m_eventList, 1);

    splitter->addWidget(lowerPanel);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    mainLayout->addWidget(splitter);

    connect(m_slider, &QSlider::valueChanged,
            this, &GeoOverviewDialog::onSliderValueChanged);
    connect(m_eventList, &QListWidget::currentRowChanged,
            this, &GeoOverviewDialog::onEventSelectionChanged);
    connect(m_playButton, &QPushButton::clicked,
            this, &GeoOverviewDialog::togglePlayback);
    connect(m_nextButton, &QPushButton::clicked,
            this, &GeoOverviewDialog::playNext);
    connect(m_prevButton, &QPushButton::clicked,
            this, &GeoOverviewDialog::playPrevious);

    buildEvents(model, geo);
    updateControlsState();

    if (!m_events.isEmpty()) {
        setCurrentEvent(0, false);
    } else {
        m_map->highlightCountries({});
        m_map->clearOverlay();
        m_infoLabel->setText(tr("No packets with geolocation data captured yet."));
        m_detailLabel->setText(tr("Capture some traffic or load a PCAP to explore the world view."));
    }
}

void GeoOverviewDialog::buildEvents(PacketTableModel *model, GeoLocation *geo)
{
    m_eventList->clear();
    m_events.clear();

    if (!model || !geo)
        return;

    const QLocale locale = QLocale::c();
    const int rowCount = model->rowCount();
    m_events.reserve(rowCount);

    for (int rowIndex = 0; rowIndex < rowCount; ++rowIndex) {
        PacketTableRow row = model->row(rowIndex);
        FlightEvent event;
        event.packetNumber = row.columns.value(ColumnNumber).toInt();
        event.timeStamp = row.columns.value(ColumnTime);
        event.srcIp = row.columns.value(ColumnSource);
        event.dstIp = row.columns.value(ColumnDestination);
        event.protocol = row.columns.value(ColumnProtocol);
        event.length = row.columns.value(ColumnLength);
        event.info = row.columns.value(ColumnInfo);

        bool ok = false;
        event.timeSeconds = locale.toDouble(event.timeStamp, &ok);
        if (!ok)
            event.timeSeconds = event.timeStamp.toDouble(&ok);
        if (!ok)
            event.timeSeconds = 0.0;

        const QVector<GeoStruct> geoInfo = geo->GeoVector(event.srcIp, event.dstIp);
        for (const GeoStruct &gs : geoInfo) {
            const bool isSource = gs.name.startsWith(QStringLiteral("Source IP"));
            const bool isDestination = gs.name.startsWith(QStringLiteral("Destination IP"));

            QString country;
            double latitude = std::numeric_limits<double>::quiet_NaN();
            double longitude = std::numeric_limits<double>::quiet_NaN();

            for (const auto &field : gs.fields) {
                if (field.first == QStringLiteral("Country")) {
                    country = field.second;
                } else if (field.first == QStringLiteral("Latitude")) {
                    bool latOk = false;
                    latitude = locale.toDouble(field.second, &latOk);
                    if (!latOk)
                        latitude = field.second.toDouble(&latOk);
                    if (!latOk)
                        latitude = std::numeric_limits<double>::quiet_NaN();
                } else if (field.first == QStringLiteral("Longitude")) {
                    bool lonOk = false;
                    longitude = locale.toDouble(field.second, &lonOk);
                    if (!lonOk)
                        longitude = field.second.toDouble(&lonOk);
                    if (!lonOk)
                        longitude = std::numeric_limits<double>::quiet_NaN();
                }
            }

            auto maybeIso = CountryMap::nameToIso().find(country);
            if (maybeIso != CountryMap::nameToIso().end())
                event.isoCodes << *maybeIso;

            if (isSource) {
                event.srcCountry = country;
                event.srcLat = latitude;
                event.srcLon = longitude;
            } else if (isDestination) {
                event.dstCountry = country;
                event.dstLat = latitude;
                event.dstLon = longitude;
            }
        }

        event.isoCodes.removeDuplicates();
        event.hasCoordinates = std::isfinite(event.srcLat) && std::isfinite(event.srcLon)
                            && std::isfinite(event.dstLat) && std::isfinite(event.dstLon);

        m_events.push_back(event);
    }

    if (m_events.isEmpty()) {
        auto *placeholder = new QListWidgetItem(tr("No packets with geolocation data available."));
        placeholder->setFlags(Qt::NoItemFlags);
        m_eventList->addItem(placeholder);
        return;
    }

    for (int i = 0; i < m_events.size(); ++i) {
        const FlightEvent &event = m_events.at(i);
        const QString srcLabel = formatCountryLabel(event.srcCountry, event.srcIp);
        const QString dstLabel = formatCountryLabel(event.dstCountry, event.dstIp);
        QString display = tr("%1. %2 → %3 (%4)")
            .arg(event.packetNumber)
            .arg(event.srcIp)
            .arg(event.dstIp)
            .arg(event.protocol);
        auto *item = new QListWidgetItem(display);
        item->setToolTip(tr("%1 → %2\nCountries: %3 → %4")
                         .arg(event.srcIp,
                              event.dstIp,
                              srcLabel,
                              dstLabel));
        m_eventList->addItem(item);
    }
}

void GeoOverviewDialog::updateControlsState()
{
    const bool hasEvents = !m_events.isEmpty();
    m_slider->setEnabled(hasEvents);
    m_playButton->setEnabled(hasEvents);
    m_prevButton->setEnabled(hasEvents);
    m_nextButton->setEnabled(hasEvents);

    if (hasEvents) {
        m_slider->setRange(0, m_events.size() - 1);
    } else {
        m_slider->setRange(0, 0);
        m_slider->setValue(0);
    }

    m_playButton->setText(m_isPlaying ? tr("Pause") : tr("Play"));
}

void GeoOverviewDialog::setCurrentEvent(int index, bool userInitiated)
{
    if (m_events.isEmpty())
        return;

    if (index < 0)
        index = 0;
    if (index >= m_events.size())
        index = m_events.size() - 1;

    if (userInitiated && m_isPlaying) {
        m_isPlaying = false;
        m_map->stopFlightAnimation();
    }

    m_currentIndex = index;

    {
        QSignalBlocker blockSlider(m_slider);
        m_slider->setValue(index);
    }
    {
        QSignalBlocker blockList(m_eventList);
        m_eventList->setCurrentRow(index);
    }

    updateMapForEvent(m_events.at(index));
    updateControlsState();
}

void GeoOverviewDialog::updateMapForEvent(const FlightEvent &event)
{
    if (!m_map)
        return;

    if (!event.isoCodes.isEmpty())
        m_map->highlightCountries(event.isoCodes);
    else
        m_map->highlightCountries({});

    const QString srcLabel = formatCountryLabel(event.srcCountry, event.srcIp);
    const QString dstLabel = formatCountryLabel(event.dstCountry, event.dstIp);

    QString headline = tr("Packet %1 • %2 s • %3 → %4")
        .arg(event.packetNumber)
        .arg(QString::number(event.timeSeconds, 'f', 3))
        .arg(event.srcIp)
        .arg(event.dstIp);
    QString details = tr("Protocol: %1 • Length: %2 bytes")
        .arg(event.protocol)
        .arg(event.length);
    if (!event.info.trimmed().isEmpty()) {
        details.append(tr("\nInfo: %1").arg(event.info));
    }

    QString countryLine = tr("Route: %1 → %2")
        .arg(srcLabel)
        .arg(dstLabel);

    m_infoLabel->setText(headline);
    m_detailLabel->setText(countryLine + QLatin1Char('\n') + details);

    if (event.hasCoordinates) {
        const QString flightLabel = tr("%1 → %2").arg(srcLabel, dstLabel);
        m_map->displayFlightPath(event.srcLat, event.srcLon,
                                 event.dstLat, event.dstLon,
                                 flightLabel);
    } else {
        m_map->clearOverlay();
        m_map->stopFlightAnimation();
        if (m_isPlaying) {
            QTimer::singleShot(600, this, &GeoOverviewDialog::handleFlightFinished);
        }
    }
}

void GeoOverviewDialog::onSliderValueChanged(int value)
{
    setCurrentEvent(value, true);
}

void GeoOverviewDialog::onEventSelectionChanged(int row)
{
    if (row < 0)
        return;
    setCurrentEvent(row, true);
}

void GeoOverviewDialog::togglePlayback()
{
    if (m_events.isEmpty())
        return;

    m_isPlaying = !m_isPlaying;
    m_playButton->setText(m_isPlaying ? tr("Pause") : tr("Play"));

    if (m_isPlaying) {
        int targetIndex = m_currentIndex;
        if (targetIndex < 0)
            targetIndex = 0;
        setCurrentEvent(targetIndex, false);
    } else {
        m_map->stopFlightAnimation();
    }
}

void GeoOverviewDialog::playNext()
{
    if (m_events.isEmpty())
        return;

    if (m_isPlaying) {
        m_isPlaying = false;
        m_playButton->setText(tr("Play"));
        m_map->stopFlightAnimation();
    }

    int nextIndex = m_currentIndex + 1;
    if (nextIndex >= m_events.size())
        nextIndex = 0;
    setCurrentEvent(nextIndex, true);
}

void GeoOverviewDialog::playPrevious()
{
    if (m_events.isEmpty())
        return;

    if (m_isPlaying) {
        m_isPlaying = false;
        m_playButton->setText(tr("Play"));
        m_map->stopFlightAnimation();
    }

    int prevIndex = m_currentIndex - 1;
    if (prevIndex < 0)
        prevIndex = m_events.size() - 1;
    setCurrentEvent(prevIndex, true);
}

void GeoOverviewDialog::handleFlightFinished()
{
    if (!m_isPlaying || m_events.isEmpty())
        return;

    int nextIndex = m_currentIndex + 1;
    if (nextIndex >= m_events.size())
        nextIndex = 0;

    if (nextIndex == m_currentIndex) {
        m_isPlaying = false;
        m_playButton->setText(tr("Play"));
        return;
    }

    setCurrentEvent(nextIndex, false);
}
