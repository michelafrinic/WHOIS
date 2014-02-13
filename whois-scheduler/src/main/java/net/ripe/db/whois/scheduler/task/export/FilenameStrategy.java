package net.ripe.db.whois.scheduler.task.export;

import net.ripe.db.whois.common.rpsl.ObjectType;

interface FilenameStrategy {
    class SplitFile implements FilenameStrategy {
        @Override
        public String getFilename(final ObjectType objectType) {
            return "afrinic.db." + objectType.getName();
        }
    }

    class SingleFile implements FilenameStrategy {
        @Override
        public String getFilename(final ObjectType objectType) {
            return "afrinic.db";
        }
    }

    String getFilename(ObjectType objectType);
}
