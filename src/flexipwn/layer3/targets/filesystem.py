import fnmatch

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.targets.base import TargetEvaluator


class FileCreatedEvaluator(TargetEvaluator):
    """
    Matchea eventos file_created.

    Si config.path termina en '/': verifica que details["path"] esté bajo ese
    directorio y que el nombre del archivo haga match con config.pattern
    (si pattern es None, cualquier archivo en ese directorio cuenta).

    Si config.path NO termina en '/': verifica igualdad exacta de path.
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "file_created":
            return False
        event_path: str = event.details.get("path", "")
        config_path = self.config.path or ""
        if config_path.endswith("/"):
            dir_prefix = config_path.rstrip("/")
            # El evento debe estar directamente bajo el directorio
            if not event_path.startswith(config_path) and not event_path.startswith(dir_prefix + "/"):
                return False
            filename = event_path.rsplit("/", 1)[-1]
            if self.config.pattern is not None:
                return fnmatch.fnmatch(filename, self.config.pattern)
            return True
        else:
            return event_path == config_path


class FileModifiedEvaluator(TargetEvaluator):
    """
    Matchea eventos file_modified. Solo tiene sentido con paths exactos.

    Si config.path termina en '/': aplica misma lógica de directorio que
    FileCreatedEvaluator (sin soporte de pattern — file_modified en un
    directorio cualquiera es válido).
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "file_modified":
            return False
        event_path: str = event.details.get("path", "")
        config_path = self.config.path or ""
        if config_path.endswith("/"):
            return event_path.startswith(config_path) or event_path.startswith(config_path.rstrip("/") + "/")
        else:
            return event_path == config_path


class FileExistsEvaluator(TargetEvaluator):
    """
    Matchea eventos file_exists (polling).

    Verifica que details["path"] == config.path.
    Si config.contains está definido, verifica que sea substring de
    details["content"]. Si content es None, no matchea.
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "file_exists":
            return False
        event_path: str = event.details.get("path", "")
        if event_path != self.config.path:
            return False
        if self.config.contains is not None:
            content = event.details.get("content")
            if content is None:
                return False
            return self.config.contains in content
        return True
