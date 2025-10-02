#include "GeoMap.h"

GeoMapWidget::GeoMapWidget(const QString &svgMapFile, QWidget *parent)
    : QGraphicsView(parent),
      scene(new QGraphicsScene(this)),
      svgRenderer(new QSvgRenderer(this)),
      mapItem(new QGraphicsSvgItem())
{
    QFile f(svgMapFile);
    if (f.open(QIODevice::ReadOnly)) {
        originalSvgData = f.readAll();
        originalDoc.setContent(originalSvgData);
        f.close();
    }

    svgRenderer->load(originalSvgData);
    mapItem->setSharedRenderer(svgRenderer);
    scene->addItem(mapItem);
    scene->setSceneRect(mapItem->boundingRect());

    setScene(scene);
    fitInView(mapItem->boundingRect(), Qt::KeepAspectRatio);
}

void GeoMapWidget::highlightCountries(const QStringList &countryIds)
{
    
    QDomDocument doc = originalDoc;
    QDomElement root = doc.documentElement();
    for (const QString &cid : countryIds) {
        QDomElement group = findElementById(root, cid);
        if (group.isNull())
            continue;

        QDomNodeList paths = group.elementsByTagName("path");
        for (int i = 0; i < paths.count(); ++i) {
            QDomElement path = paths.at(i).toElement();
            QString style = path.attribute("style");

            if (!style.isEmpty()) {
                if (style.contains("fill:")) {
                    style.replace(QRegularExpression("fill:[^;]+"),
                                  "fill:#FF0000");
                } else {
                    style += ";fill:#FF0000";
                }
                path.setAttribute("style", style);
            } else {
                path.setAttribute("fill", "#FF0000");
            }
        }
    }
    QByteArray newSvg = doc.toByteArray();
    svgRenderer->load(newSvg);
    mapItem->update();
}

void GeoMapWidget::resizeEvent(QResizeEvent *event)
{
    QGraphicsView::resizeEvent(event);
    fitInView(mapItem->boundingRect(), Qt::KeepAspectRatio);
}

QDomElement GeoMapWidget::findElementById(const QDomElement &parent,
                                          const QString &id)
{
    if (parent.attribute("id") == id)
        return parent;

    QDomElement child = parent.firstChildElement();
    while (!child.isNull()) {
        QDomElement found = findElementById(child, id);
        if (!found.isNull())
            return found;
        child = child.nextSiblingElement();
    }
    return QDomElement();
}
