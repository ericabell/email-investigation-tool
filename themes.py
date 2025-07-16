"""Theme system for light/dark mode terminal compatibility."""

from dataclasses import dataclass
from rich.theme import Theme
from rich.style import Style

@dataclass
class ThemeColors:
    """Color definitions for a theme."""
    # Basic colors
    background: str
    foreground: str
    
    # Panel colors
    panel_border: str
    panel_title: str
    panel_background: str
    
    # Status colors
    success: str
    warning: str
    error: str
    info: str
    
    # SMTP protocol colors
    smtp_outgoing: str
    smtp_incoming: str
    smtp_error: str
    smtp_timing: str
    
    # UI elements
    button_active: str
    button_inactive: str
    input_field: str
    highlight: str
    
    # Data visualization
    progress_bar: str
    metric_value: str
    metric_label: str

# Dark theme (default)
DARK_THEME = ThemeColors(
    background="black",
    foreground="white",
    
    panel_border="bright_blue",
    panel_title="bright_cyan",
    panel_background="grey11",
    
    success="bright_green",
    warning="bright_yellow",
    error="bright_red",
    info="bright_blue",
    
    smtp_outgoing="bright_cyan",
    smtp_incoming="bright_green",
    smtp_error="bright_red",
    smtp_timing="dim yellow",
    
    button_active="bright_green",
    button_inactive="grey50",
    input_field="white on blue",
    highlight="bright_yellow",
    
    progress_bar="bright_blue",
    metric_value="bright_white",
    metric_label="grey70"
)

# Light theme
LIGHT_THEME = ThemeColors(
    background="white",
    foreground="black",
    
    panel_border="blue",
    panel_title="dark_blue",
    panel_background="grey93",
    
    success="dark_green",
    warning="dark_orange",
    error="dark_red",
    info="dark_blue",
    
    smtp_outgoing="dark_cyan",
    smtp_incoming="dark_green",
    smtp_error="dark_red",
    smtp_timing="dim black",
    
    button_active="dark_green",
    button_inactive="grey50",
    input_field="black on light_blue",
    highlight="dark_orange",
    
    progress_bar="dark_blue",
    metric_value="black",
    metric_label="grey30"
)

class ThemeManager:
    """Manages theme switching and provides Rich theme objects."""
    
    def __init__(self, default_theme: str = "dark"):
        self.current_theme_name = default_theme
        self.current_theme = DARK_THEME if default_theme == "dark" else LIGHT_THEME
        self.rich_theme = self._create_rich_theme()
    
    def toggle_theme(self):
        """Toggle between light and dark themes."""
        if self.current_theme_name == "dark":
            self.set_theme("light")
        else:
            self.set_theme("dark")
    
    def set_theme(self, theme_name: str):
        """Set the theme to light or dark."""
        self.current_theme_name = theme_name
        self.current_theme = DARK_THEME if theme_name == "dark" else LIGHT_THEME
        self.rich_theme = self._create_rich_theme()
    
    def _create_rich_theme(self) -> Theme:
        """Create a Rich theme object from current theme colors."""
        return Theme({
            # Basic styles
            "panel.border": self.current_theme.panel_border,
            "panel.title": self.current_theme.panel_title,
            "panel.background": self.current_theme.panel_background,
            
            # Status styles
            "status.success": self.current_theme.success,
            "status.warning": self.current_theme.warning,
            "status.error": self.current_theme.error,
            "status.info": self.current_theme.info,
            
            # SMTP protocol styles
            "smtp.outgoing": self.current_theme.smtp_outgoing,
            "smtp.incoming": self.current_theme.smtp_incoming,
            "smtp.error": self.current_theme.smtp_error,
            "smtp.timing": self.current_theme.smtp_timing,
            
            # UI element styles
            "button.active": self.current_theme.button_active,
            "button.inactive": self.current_theme.button_inactive,
            "input": self.current_theme.input_field,
            "highlight": self.current_theme.highlight,
            
            # Data visualization
            "progress": self.current_theme.progress_bar,
            "metric.value": self.current_theme.metric_value,
            "metric.label": self.current_theme.metric_label,
            
            # General text
            "text": self.current_theme.foreground,
            "background": self.current_theme.background,
        })
    
    def get_progress_style(self) -> str:
        """Get the progress bar style for current theme."""
        return self.current_theme.progress_bar
    
    def get_panel_style(self) -> str:
        """Get the panel border style for current theme."""
        return self.current_theme.panel_border
    
    def get_title_style(self) -> str:
        """Get the title style for current theme."""
        return self.current_theme.panel_title
    
    def get_smtp_outgoing_style(self) -> str:
        """Get the SMTP outgoing message style."""
        return self.current_theme.smtp_outgoing
    
    def get_smtp_incoming_style(self) -> str:
        """Get the SMTP incoming message style."""
        return self.current_theme.smtp_incoming
    
    def get_smtp_error_style(self) -> str:
        """Get the SMTP error message style."""
        return self.current_theme.smtp_error
    
    def get_smtp_timing_style(self) -> str:
        """Get the SMTP timing info style."""
        return self.current_theme.smtp_timing
    
    def get_success_style(self) -> str:
        """Get the success message style."""
        return self.current_theme.success
    
    def get_error_style(self) -> str:
        """Get the error message style."""
        return self.current_theme.error
    
    def get_warning_style(self) -> str:
        """Get the warning message style."""
        return self.current_theme.warning
    
    def get_info_style(self) -> str:
        """Get the info message style."""
        return self.current_theme.info