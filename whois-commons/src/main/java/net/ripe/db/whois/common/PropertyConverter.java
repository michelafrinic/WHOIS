package net.ripe.db.whois.common;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by yogesh on 6/11/14.
 */
@Component
public class PropertyConverter {

    private ObjectMapper jacksonObjectMapper = new ObjectMapper();

    public Map<String,String> jsonToPropertyMap(String jsonProperty) throws IOException {
        return jacksonObjectMapper.readValue(jsonProperty,
                new TypeReference<HashMap<String,String>>(){});
    }

    public Pattern stringToPattern(String propertyPattern) {

        if (propertyPattern == null ||
                "".equals(propertyPattern.trim())) {
            return null;
        }

        return Pattern.compile(propertyPattern, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    }
}
