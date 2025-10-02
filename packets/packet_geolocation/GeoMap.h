#ifndef GEOMAP_H
#define GEOMAP_H

#include <QGraphicsView>
#include <QtSvgWidgets/QGraphicsSvgItem>
#include <QtSvg/QSvgRenderer>
#include <QtXml/QDomDocument>
#include <QStringList>
#include <QByteArray>
#include <QFile>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QDomDocument>
#include <QDomElement>
#include <QDomNodeList>

class GeoMapWidget : public QGraphicsView {
    Q_OBJECT
public:
    explicit GeoMapWidget(const QString &svgMapFile, QWidget *parent = nullptr);

    void highlightCountries(const QStringList &countryIds);

protected:
    void resizeEvent(QResizeEvent *event) override;

private:
    QDomElement findElementById(const QDomElement &parent, const QString &id);

    QGraphicsScene      *scene;
    QSvgRenderer        *svgRenderer;
    QGraphicsSvgItem    *mapItem;
    QByteArray           originalSvgData;
    QDomDocument         originalDoc;
};
#endif //GEOMAP_H