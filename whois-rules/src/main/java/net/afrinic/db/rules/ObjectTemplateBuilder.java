package net.afrinic.db.rules;

import net.ripe.db.whois.common.rpsl.AttributeTemplate;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by yogesh on 4/8/14.
 */
public final class ObjectTemplateBuilder {

    public static final ObjectTemplate[] buildObjectTemplateArray(WhoisRules whoisRules) {
        Map<ObjectType,Set<AttributeTemplate>> mapA = new HashMap<>();

        AttributeTemplate[] attributeTemplates = whoisRules.getAttributeTemplates();
        for (AttributeTemplate attributeTemplate: attributeTemplates) {
            ObjectType objectType = attributeTemplate.getObjectType();
            if (!mapA.containsKey(objectType))  {
                mapA.put(objectType, new LinkedHashSet<AttributeTemplate>());
            }
            mapA.get(objectType).add(attributeTemplate);

            System.out.println(attributeTemplate);
        }

        ObjectTemplate[] objectTemplates = whoisRules.getObjectTemplates();
        for (ObjectTemplate objectTemplate: objectTemplates) {
            ObjectType objectType =  objectTemplate.getObjectType();
            if (mapA.containsKey(objectType)) {
                objectTemplate.setAttributeTemplates(mapA.get(objectType).toArray(new AttributeTemplate[0]));
            }
        }

        return objectTemplates;
    }
}
