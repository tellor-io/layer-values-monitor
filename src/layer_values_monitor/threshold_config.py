"""Threshold configuration for the Layer Values Monitor."""


class ThresholdConfig:
    """Configuration for global threshold values."""

    def __init__(
        self,
        # percentage thresholds
        percentage_alert: float | None = None,
        percentage_warning: float | None = None,
        percentage_minor: float | None = None,
        percentage_major: float | None = None,
        # range thresholds
        range_alert: float | None = None,
        range_warning: float | None = None,
        range_minor: float | None = None,
        range_major: float | None = None,
        # equality thresholds
        equality_alert: float | None = None,
        equality_warning: float | None = None,
        equality_minor: float | None = None,
        equality_major: float | None = None,
    ) -> None:
        """Initialize the ThresholdConfig with default values."""
        # Set all properties
        self.percentage_alert = percentage_alert
        self.percentage_warning = percentage_warning
        self.percentage_minor = percentage_minor
        self.percentage_major = percentage_major

        self.range_alert = range_alert
        self.range_warning = range_warning
        self.range_minor = range_minor
        self.range_major = range_major

        self.equality_alert = equality_alert
        self.equality_warning = equality_warning
        self.equality_minor = equality_minor
        self.equality_major = equality_major

    @classmethod
    def from_args(cls, args: object) -> "ThresholdConfig":
        """Create a config from parsed command line arguments."""
        if args.use_custom_config:
            return cls()

        # Check if required values are present
        if any(
            [
                args.global_percentage_alert_threshold is None,
                args.global_range_alert_threshold is None,
                args.global_equality_alert_threshold is None,
                # percentage
                args.global_percentage_warning_threshold is None,
                args.global_percentage_minor_threshold is None,
                args.global_percentage_major_threshold is None,
                # range
                args.global_range_warning_threshold is None,
                args.global_range_minor_threshold is None,
                args.global_range_major_threshold is None,
                # equality
                args.global_equality_warning_threshold is None,
                args.global_equality_minor_threshold is None,
                args.global_equality_major_threshold is None,
            ]
        ):
            raise ValueError("Global alert threshold flags required if not using custom config")

        return cls(
            # Percentage thresholds
            percentage_alert=args.global_percentage_alert_threshold,
            percentage_warning=args.global_percentage_warning_threshold,
            percentage_minor=args.global_percentage_minor_threshold,
            percentage_major=args.global_percentage_major_threshold,
            # Range thresholds
            range_alert=args.global_range_alert_threshold,
            range_warning=args.global_range_warning_threshold,
            range_minor=args.global_range_minor_threshold,
            range_major=args.global_range_major_threshold,
            # Equality thresholds
            equality_alert=args.global_equality_alert_threshold,
            equality_warning=args.global_equality_warning_threshold,
            equality_minor=args.global_equality_minor_threshold,
            equality_major=args.global_equality_major_threshold,
        )
