package net.afrinic.db.whois.common.rpsl.impl;

import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.impl.RipeObjectTypeFactory;

import java.util.List;

/**
 * Created by michel on 7/15/14.
 */
public class AfrinicObjectTypeFactory extends RipeObjectTypeFactory {
    public AfrinicObjectTypeFactory(List<IObjectType> objectTypes) {
        super(objectTypes);
    }

    @Override
    public IObjectType get(Class<? extends IObjectType> clazz) {
        return TYPE_CLASSES.get(moreSpecificLookup(clazz));
    }

    private Class moreSpecificLookup(Class<? extends IObjectType> clazz) {
        for(Class typeClass : TYPE_CLASSES.keySet()) {
            Class superClass = typeClass.getSuperclass();
            if(superClass.equals(clazz)) {
                return moreSpecificLookup(typeClass);
            }
        }
        return clazz;
    }
}
