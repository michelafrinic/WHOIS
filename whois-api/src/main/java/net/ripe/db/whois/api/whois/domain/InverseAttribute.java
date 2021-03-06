package net.ripe.db.whois.api.whois.domain;

import javax.xml.bind.annotation.*;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "inverse-attribute")
public class InverseAttribute {

    @XmlAttribute(name = "value", required = true)
    protected String value;

    public InverseAttribute(final String value) {
        this.value = value;
    }

    public InverseAttribute() {
        // required no-arg constructor
    }

    public String getValue() {
        return value;
    }
}
