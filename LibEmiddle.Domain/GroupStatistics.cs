using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Statistics and insights about a group session (v2.5).
    /// Provides analytics for group activity, member engagement, and health metrics.
    /// </summary>
    public class GroupStatistics
    {
        /// <summary>
        /// Total number of members in the group.
        /// </summary>
        public int TotalMembers { get; set; }

        /// <summary>
        /// Number of active members (those who have sent messages recently).
        /// </summary>
        public int ActiveMembers { get; set; }

        /// <summary>
        /// Number of currently muted members.
        /// </summary>
        public int MutedMembers { get; set; }

        /// <summary>
        /// Breakdown of members by role.
        /// </summary>
        public Dictionary<MemberRole, int> MembersByRole { get; set; } = new();

        /// <summary>
        /// Total number of messages sent in the group.
        /// </summary>
        public long TotalMessages { get; set; }

        /// <summary>
        /// Number of messages sent in the last 24 hours.
        /// </summary>
        public long MessagesLast24Hours { get; set; }

        /// <summary>
        /// Number of messages sent in the last 7 days.
        /// </summary>
        public long MessagesLast7Days { get; set; }

        /// <summary>
        /// Number of messages sent in the last 30 days.
        /// </summary>
        public long MessagesLast30Days { get; set; }

        /// <summary>
        /// Average messages per day over the last 30 days.
        /// </summary>
        public double AverageMessagesPerDay { get; set; }

        /// <summary>
        /// Most active member (by message count).
        /// </summary>
        public byte[]? MostActiveMember { get; set; }

        /// <summary>
        /// Message count for the most active member.
        /// </summary>
        public long MostActiveMemberMessageCount { get; set; }

        /// <summary>
        /// When the group was created.
        /// </summary>
        public DateTime GroupCreatedAt { get; set; }

        /// <summary>
        /// When the last message was sent.
        /// </summary>
        public DateTime? LastMessageAt { get; set; }

        /// <summary>
        /// When the last member joined.
        /// </summary>
        public DateTime? LastMemberJoinedAt { get; set; }

        /// <summary>
        /// Number of times keys have been rotated.
        /// </summary>
        public int KeyRotationCount { get; set; }

        /// <summary>
        /// When keys were last rotated.
        /// </summary>
        public DateTime? LastKeyRotationAt { get; set; }

        /// <summary>
        /// Number of active invitations.
        /// </summary>
        public int ActiveInvitations { get; set; }

        /// <summary>
        /// Number of members who joined via invitation.
        /// </summary>
        public int MembersJoinedViaInvitation { get; set; }

        /// <summary>
        /// Health score of the group (0-100).
        /// Based on activity levels, key rotation frequency, and member engagement.
        /// </summary>
        public int HealthScore { get; set; }

        /// <summary>
        /// Additional provider-specific statistics.
        /// </summary>
        public Dictionary<string, object> AdditionalMetrics { get; set; } = new();

        /// <summary>
        /// When these statistics were generated.
        /// </summary>
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Calculates member activity rate (active members / total members).
        /// </summary>
        public double MemberActivityRate => TotalMembers > 0 ? (double)ActiveMembers / TotalMembers : 0.0;

        /// <summary>
        /// Calculates group engagement score based on message frequency and member activity.
        /// </summary>
        public double EngagementScore
        {
            get
            {
                if (TotalMembers == 0) return 0.0;

                var activityFactor = MemberActivityRate;
                var messagingFactor = Math.Min(1.0, AverageMessagesPerDay / 10.0); // Normalize to 10 messages/day = 100%
                var freshnessFactor = LastMessageAt.HasValue ? 
                    Math.Max(0.0, 1.0 - (DateTime.UtcNow - LastMessageAt.Value).TotalDays / 7.0) : 0.0;

                return (activityFactor * 0.4 + messagingFactor * 0.4 + freshnessFactor * 0.2) * 100;
            }
        }

        /// <summary>
        /// Gets health indicators for the group.
        /// </summary>
        public List<string> GetHealthIndicators()
        {
            var indicators = new List<string>();

            if (MemberActivityRate < 0.3)
                indicators.Add("Low member activity rate");

            if (LastMessageAt.HasValue && (DateTime.UtcNow - LastMessageAt.Value).TotalDays > 7)
                indicators.Add("No recent messages");

            if (KeyRotationCount == 0 && (DateTime.UtcNow - GroupCreatedAt).TotalDays > 30)
                indicators.Add("Keys have never been rotated");

            if (LastKeyRotationAt.HasValue && (DateTime.UtcNow - LastKeyRotationAt.Value).TotalDays > 90)
                indicators.Add("Keys not rotated recently");

            if (TotalMembers > 10 && !MembersByRole.ContainsKey(MemberRole.Admin))
                indicators.Add("Large group without administrators");

            if (MutedMembers > TotalMembers * 0.2)
                indicators.Add("High percentage of muted members");

            return indicators;
        }

        /// <summary>
        /// Creates a summary report of the group statistics.
        /// </summary>
        public string GenerateReport()
        {
            var report = new System.Text.StringBuilder();
            
            report.AppendLine($"Group Statistics Report - Generated: {GeneratedAt:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine(new string('=', 60));
            report.AppendLine();

            // Member statistics
            report.AppendLine("MEMBER STATISTICS:");
            report.AppendLine($"  Total Members: {TotalMembers}");
            report.AppendLine($"  Active Members: {ActiveMembers} ({MemberActivityRate:P1})");
            report.AppendLine($"  Muted Members: {MutedMembers}");
            report.AppendLine();

            // Role breakdown
            if (MembersByRole.Any())
            {
                report.AppendLine("ROLE BREAKDOWN:");
                foreach (var kvp in MembersByRole.OrderByDescending(x => (int)x.Key))
                {
                    report.AppendLine($"  {kvp.Key}: {kvp.Value}");
                }
                report.AppendLine();
            }

            // Message statistics
            report.AppendLine("MESSAGE STATISTICS:");
            report.AppendLine($"  Total Messages: {TotalMessages:N0}");
            report.AppendLine($"  Last 24 Hours: {MessagesLast24Hours:N0}");
            report.AppendLine($"  Last 7 Days: {MessagesLast7Days:N0}");
            report.AppendLine($"  Last 30 Days: {MessagesLast30Days:N0}");
            report.AppendLine($"  Average per Day: {AverageMessagesPerDay:F1}");
            report.AppendLine();

            // Health indicators
            var indicators = GetHealthIndicators();
            if (indicators.Any())
            {
                report.AppendLine("HEALTH INDICATORS:");
                foreach (var indicator in indicators)
                {
                    report.AppendLine($"  ⚠️  {indicator}");
                }
                report.AppendLine();
            }

            // Scores
            report.AppendLine("SCORES:");
            report.AppendLine($"  Health Score: {HealthScore}/100");
            report.AppendLine($"  Engagement Score: {EngagementScore:F1}/100");

            return report.ToString();
        }
    }
}