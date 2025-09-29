import asyncio
from datetime import datetime, time, timedelta
from typing import Optional, Dict, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import EmailConfig, WorkerStatus
from app.core.security import SecurityManager
from app.services.email_service import email_service


class EmailWorker:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EmailWorker, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.scheduler = AsyncIOScheduler()
        self.is_processing = False
        self.config: Optional[EmailConfig] = None
        self.security_manager = SecurityManager()
        self.started_at: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self.next_run: Optional[datetime] = None
        self._initialized = True

    @classmethod
    def get_instance(cls):
        """Get singleton instance of EmailWorker"""
        return cls()

    async def load_email_config(self) -> Optional[EmailConfig]:
        """Load email configuration from encrypted storage"""
        config_data = self.security_manager.load_encrypted_config("email")
        if config_data:
            self.config = EmailConfig(**config_data)
            return self.config
        return None

    async def start(self):
        """Start the email worker with scheduled processing"""
        try:
            # Load configuration
            config = await self.load_email_config()
            if not config:
                raise Exception("Email configuration not found")

            self.config = config
            self.started_at = datetime.now()

            # Setup scheduler
            await self._setup_scheduler()

            # Start the scheduler
            if not self.scheduler.running:
                self.scheduler.start()

            print(f"Email worker started at {self.started_at}")
            print(f"Schedule: {config.start_time} to {config.end_time}, every {config.interval} {config.interval_unit}")

        except Exception as e:
            raise Exception(f"Failed to start email worker: {str(e)}")

    async def stop(self):
        """Stop the email worker and clear schedules"""
        try:
            if self.scheduler.running:
                self.scheduler.shutdown(wait=False)

            self.started_at = None
            self.last_activity = None
            self.next_run = None
            self.is_processing = False

            print("Email worker stopped")

        except Exception as e:
            print(f"Error stopping email worker: {e}")

    async def get_status(self) -> WorkerStatus:
        """Get current worker status"""
        status = "stopped"
        if self.scheduler.running:
            status = "running" if not self.is_processing else "processing"

        # Get next run time from scheduler
        jobs = self.scheduler.get_jobs()
        next_run = None
        if jobs:
            try:
                next_run = getattr(jobs[0], 'next_run_time', None)
            except AttributeError:
                next_run = None

        return WorkerStatus(
            status=status,
            started_at=self.started_at,
            last_activity=self.last_activity,
            next_run=next_run,
            is_processing=self.is_processing
        )

    async def force_process_emails(self):
        """Force process emails immediately"""
        if self.is_processing:
            return {"message": "Email processing is already in progress"}

        try:
            self.is_processing = True
            self.last_activity = datetime.now()

            # Process emails
            stats = await email_service.process_email_queue()

            return {
                "message": "Email processing completed successfully",
                "processed": stats.processed,
                "success": stats.success,
                "failed": stats.failed,
                "timestamp": datetime.now()
            }

        except Exception as e:
            return {
                "message": f"Email processing failed: {str(e)}",
                "timestamp": datetime.now()
            }
        finally:
            self.is_processing = False

    def is_within_schedule(self, start_time: str, end_time: str) -> bool:
        """Check if current time is within service schedule"""
        try:
            current_time = datetime.now().time()
            start = datetime.strptime(start_time, "%H:%M").time()
            end = datetime.strptime(end_time, "%H:%M").time()

            if start <= end:
                # Same day schedule
                return start <= current_time <= end
            else:
                # Overnight schedule (crosses midnight)
                return current_time >= start or current_time <= end

        except Exception as e:
            print(f"Error checking schedule: {e}")
            return False

    async def _setup_scheduler(self):
        """Setup the email processing scheduler"""
        if not self.config:
            raise Exception("Email configuration not loaded")

        # Clear existing jobs
        self.scheduler.remove_all_jobs()

        # Create trigger based on interval unit
        if self.config.interval_unit == "minutes":
            trigger = IntervalTrigger(minutes=self.config.interval)
        else:  # hours
            trigger = IntervalTrigger(hours=self.config.interval)

        # Add the job
        self.scheduler.add_job(
            self._scheduled_email_processing,
            trigger=trigger,
            id="email_processing_job",
            replace_existing=True,
            max_instances=1  # Prevent overlapping executions
        )

        # Update next run time
        jobs = self.scheduler.get_jobs()
        if jobs:
            try:
                self.next_run = getattr(jobs[0], 'next_run_time', None)
            except AttributeError:
                self.next_run = None

    async def _scheduled_email_processing(self):
        """Process emails based on schedule configuration"""
        try:
            # Check if we're within the scheduled time window
            if not self.is_within_schedule(self.config.start_time, self.config.end_time):
                print(f"Outside scheduled hours ({self.config.start_time} - {self.config.end_time}). Skipping email processing.")
                return

            if self.is_processing:
                print("Email processing already in progress. Skipping this run.")
                return

            print(f"Starting scheduled email processing at {datetime.now()}")

            self.is_processing = True
            self.last_activity = datetime.now()

            # Process the email queue
            stats = await email_service.process_email_queue()

            print(f"Email processing completed: {stats.processed} processed, {stats.success} sent, {stats.failed} failed")

        except Exception as e:
            print(f"Error in scheduled email processing: {e}")
        finally:
            self.is_processing = False

    def save_config(self, config: EmailConfig):
        """Save email configuration"""
        config_data = config.model_dump()
        self.security_manager.save_encrypted_config(config_data, "email")

    def config_exists(self) -> bool:
        """Check if email configuration exists"""
        return self.security_manager.config_exists("email")

    async def restart_with_new_config(self, config: EmailConfig):
        """Restart worker with new configuration"""
        # Save the new configuration
        self.save_config(config)

        # Stop current scheduler
        await self.stop()

        # Start with new configuration
        await self.start()

    async def get_schedule_info(self) -> Dict[str, Any]:
        """Get current schedule information"""
        if not self.config:
            return {"error": "No configuration loaded"}

        return {
            "start_time": self.config.start_time,
            "end_time": self.config.end_time,
            "interval": self.config.interval,
            "interval_unit": self.config.interval_unit,
            "is_active": self.scheduler.running,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "within_schedule": self.is_within_schedule(self.config.start_time, self.config.end_time)
        }


# Global email worker instance
email_worker = EmailWorker.get_instance()