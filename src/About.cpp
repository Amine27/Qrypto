// This file is part of the Qrypto project
// Copyright (C) 2008-2010 Amine Roukh <amineroukh@gmail.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 3
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; If not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


#include "About.h"


About::About(QWidget *parent) : QDialog(parent)
{
    tabs = new QTabWidget(this);
    page1 = new QWidget;
    page2 = new QWidget;
    page3 = new QWidget;

    logoImage = new QLabel();
    logoImage->setPixmap(QPixmap(":/data/qrypto.png"));
    logoText = new QLabel(tr("<h3>Qrypto - 0.4.1</h3>"));
    QHBoxLayout *logoL = new QHBoxLayout();
    logoL->addWidget(logoImage);
    logoL->addWidget(logoText, Qt::AlignLeft);

    description = new QLabel(tr("Qrypto is a simple application that allows you to encrypt or hash <br />a string text and include other encoding/decoding functions.\n"
                                "<br /><br />\nIt is powered by C++ and Qt4 and use <a href=\"http://www.cryptopp.com/\">Crypto++</a> library.<br />"));

    description->setTextFormat(Qt::RichText);
    description->setOpenExternalLinks(true);
    QFormLayout *descL = new QFormLayout();
    descL->addWidget(description);
    page1->setLayout(descL);

    tabs->addTab(page1, tr("Description"));

    authors = new QLabel(tr("<b>Amine Roukh (Amine27)</b><br />Development and GUI Design.<br /><a href=\"mailto:amineroukh@gmail.com\">amineroukh@gmail.com</a><br /><br />"));
    authors->setTextFormat(Qt::RichText);
    authors->setOpenExternalLinks(true);
    QFormLayout *authL = new QFormLayout();
    authL->addWidget(authors);
    page2->setLayout(authL);

    tabs->addTab(page2, tr("Author"));

    license = new QLabel(tr("This program is free software: you can redistribute it and/or modify it <br />under the terms of the GNU General Public License "
                            "as published by <br />the Free Software Foundation, either version 3 of the License, or  <br />(at your option) any later version.<br /><br />"
                            "You should have received a copy of the GNU General Public License <br />along with this program. If not, see <a href=\"http://www.gnu.org/licenses/\">http://www.gnu.org/licenses</a>."));
    license->setTextFormat(Qt::RichText);
    license->setOpenExternalLinks(true);
    QFormLayout *licenL = new QFormLayout();
    licenL->addWidget(license);
    page3->setLayout(licenL);

    tabs->addTab(page3, tr("License"));

    cancelButton = new QPushButton(QIcon(":/data/close.png"), tr("Close"));
    connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    buttonLayout->addWidget(cancelButton);
    buttonLayout->setAlignment(Qt::AlignRight);

    QVBoxLayout *layout = new QVBoxLayout();
    layout->addLayout(logoL);
    layout->addWidget(tabs);
    layout->addLayout(buttonLayout);

    setLayout(layout);
    setWindowTitle(tr("About Qrypto"));
}
