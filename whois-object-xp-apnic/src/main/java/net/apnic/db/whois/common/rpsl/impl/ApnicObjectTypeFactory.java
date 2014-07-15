package net.apnic.db.whois.common.rpsl.impl;

import com.google.common.base.Enums;
import com.google.common.base.Optional;
import com.google.common.collect.Lists;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Created by michel on 7/11/14.
 */
public class ApnicObjectTypeFactory implements IObjectTypeFactory {
    @Override
    public IObjectType get(Class<? extends IObjectType> clazz) {
        throw new UnsupportedOperationException("Getting an object by class is not supported by this factory.");
    }

    @Override
    public IObjectType get(String typeName) {
        IObjectType objectType = null;
        if(typeName != null) {
            Optional<ObjectTypeEnum> optional = Enums.getIfPresent(ObjectTypeEnum.class, typeName.toUpperCase());
            if(optional.isPresent()) {
                objectType = optional.get();
            }
        }
        return  objectType;
    }

    @Override
    public IObjectType get(int typeId) {
        return ObjectTypeEnum.valueOf(typeId);
    }

    @Override
    public Collection<IObjectType> values() {
        Collection<IObjectType> collection = Lists.newArrayList();
        collection.addAll(Arrays.asList(ObjectTypeEnum.values()));
        return Collections.unmodifiableCollection(collection);
    }
}
