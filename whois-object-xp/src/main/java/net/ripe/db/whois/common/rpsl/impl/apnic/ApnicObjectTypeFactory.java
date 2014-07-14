package net.ripe.db.whois.common.rpsl.impl.apnic;

import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/11/14.
 */
public class ApnicObjectTypeFactory implements IObjectTypeFactory {
    @Override
    public IObjectType get(Class<? extends IObjectType> clazz) {
        throw new UnsupportedOperationException();
    }

    @Override
    public IObjectType get(String typeName) {
        return ObjectTypeEnum.valueOf(typeName);
    }

    @Override
    public IObjectType get(int typeId) {
        return ObjectTypeEnum.valueOf(typeId);
    }
}
