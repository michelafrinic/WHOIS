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
        return TYPE_CLASSES.get(depthLookup(clazz));
    }

    private Class depthLookup(Class<? extends IObjectType> clazz) {
        int maxDepth = 0;
        Class<? extends IObjectType> returnClass = clazz;

        for(Class typeClass : TYPE_CLASSES.keySet()) {
            int depth = getAncestorDepth(clazz, typeClass);
            if(depth > maxDepth) {
                maxDepth = depth;
                returnClass = typeClass;
            }
        }
        return returnClass;
    }

    private int getAncestorDepth(Class<? extends IObjectType> ancestorClass, Class<? extends IObjectType> clazz) {
        int depth = 0;
        boolean found = false;
        for(Class superClazz = clazz.getSuperclass(); superClazz != Object.class && !found; superClazz = superClazz.getSuperclass()) {
            if(superClazz == ancestorClass) {
                found = true;
            }
            depth++;
        }
        return found ? depth : 0;
    }
}
