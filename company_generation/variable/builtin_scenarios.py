"""
Built-in email scenarios for common workplace communications.

These scenarios cover:
- Document reviews and collaboration
- Project status updates
- Bug reports and technical discussions
- Meeting follow-ups
- Cross-department coordination
- Urgent/incident scenarios

Each scenario is designed with realistic multi-participant conversations.
"""

from .email_scenarios import EmailScenario, EmailTemplate


# =============================================================================
# DOCUMENT REVIEW SCENARIOS
# =============================================================================

DOCUMENT_REVIEW_SIMPLE = EmailScenario(
    id="doc_review_simple",
    name="Simple Document Review",
    description="Quick document share with single reviewer feedback",
    num_participants=2,
    participant_roles=["author", "reviewer"],
    same_department=True,
    requires_file=True,
    file_types=["pdf", "docx", "xlsx"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Please review: {file_name}",
            body_template="""Hi {reviewer_name},

I've attached {file_name} for your review. {file_description}

Could you take a look when you have a chance? I'd appreciate feedback by {deadline}.

Thanks,
{author_name}""",
            include_attachment=True,
        ),
        EmailTemplate(
            offset_hours=5.5,
            sender_index=1,
            subject_template="Re: Please review: {file_name}",
            body_template="""Hi {author_name},

Reviewed the document. A few thoughts:

1. The section on {project_name} could use more detail on the timeline
2. Consider adding a summary table at the end
3. Minor formatting tweaks needed in section 2

Overall looks solid. Let me know if you want to discuss.

{reviewer_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=6.5,
            sender_index=0,
            subject_template="Re: Please review: {file_name}",
            body_template="""Thanks {reviewer_name}, great feedback!

I'll incorporate these changes and send the updated version tomorrow.

{author_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["review", "document", "collaboration"],
    weight=2.0,
)


DOCUMENT_REVIEW_GROUP = EmailScenario(
    id="doc_review_group",
    name="Group Document Review",
    description="Document review with multiple reviewers providing feedback",
    num_participants=4,
    participant_roles=["author", "reviewer_1", "reviewer_2", "manager"],
    same_department=True,
    requires_manager=True,
    requires_file=True,
    file_types=["pdf", "docx", "pptx"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Review requested: {file_name} - {project_name}",
            body_template="""Team,

I've completed the draft of {file_name} for {project_name}. {file_description}

Please review and provide feedback by {deadline}. Key areas I'd like input on:
- Overall structure and flow
- Accuracy of the technical details
- Any gaps in the analysis

Thanks for your help,
{author_name}""",
            include_attachment=True,
            recipient_indices=[1, 2, 3],
        ),
        EmailTemplate(
            offset_hours=3.0,
            sender_index=1,
            subject_template="Re: Review requested: {file_name} - {project_name}",
            body_template="""Thanks for sharing, {author_name}.

Quick initial feedback:
- Executive summary is clear and concise
- The data in section 3 needs a source citation
- Recommend adding a risk assessment section

Will do a more detailed pass tomorrow.

{reviewer_1_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=4.5,
            sender_index=2,
            subject_template="Re: Review requested: {file_name} - {project_name}",
            body_template="""Adding my thoughts:

- Agree with {reviewer_1_name} on the citations
- The timeline in section 4 seems optimistic - can we discuss?
- Great work on the competitive analysis

{reviewer_2_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=8.0,
            sender_index=3,
            subject_template="Re: Review requested: {file_name} - {project_name}",
            body_template="""Good work on this, {author_name}.

I've reviewed and agree with the feedback from {reviewer_1_name} and {reviewer_2_name}.

Two additional points from my perspective:
1. We should align the messaging with what we presented to the board last month
2. Please add the budget implications section before we share externally

Let's sync briefly tomorrow to finalize.

{manager_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=9.0,
            sender_index=0,
            subject_template="Re: Review requested: {file_name} - {project_name}",
            body_template="""Thank you all for the thorough feedback.

I'll address all the points raised and have an updated version ready by {deadline}.

{manager_name} - I'll set up time for us to sync tomorrow morning.

{author_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["review", "document", "collaboration", "group"],
    weight=1.5,
)


# =============================================================================
# PROJECT & STATUS UPDATE SCENARIOS
# =============================================================================

PROJECT_STATUS_UPDATE = EmailScenario(
    id="project_status_update",
    name="Project Status Update Request",
    description="Manager requests status update, team member responds",
    num_participants=2,
    participant_roles=["team_member", "manager"],
    same_department=True,
    requires_manager=True,
    requires_file=True,
    file_types=["xlsx", "pdf", "docx"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=1,  # Manager initiates
            subject_template="Status update needed: {project_name}",
            body_template="""Hi {team_member_name},

I have a leadership meeting {meeting_day} and need to provide an update on {project_name}.

Can you send me:
- Current progress against milestones
- Any blockers or risks
- Updated timeline if needed

Please send by end of day {deadline}.

Thanks,
{manager_name}""",
        ),
        EmailTemplate(
            offset_hours=3.0,
            sender_index=0,
            subject_template="Re: Status update needed: {project_name}",
            body_template="""Hi {manager_name},

Here's the update on {project_name}:

**Progress**
- Milestone 1: Complete
- Milestone 2: 80% complete, on track for {deadline}
- Milestone 3: Starting next week

**Blockers**
- Waiting on {department} team for API documentation
- Need approval for additional cloud resources

**Timeline**
Still targeting original deadline, but the blocker above could cause a 1-week slip if not resolved soon.

I've attached {file_name} with the detailed breakdown.

Let me know if you need anything else for your meeting.

{team_member_name}""",
            include_attachment=True,
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=3.5,
            sender_index=1,
            subject_template="Re: Status update needed: {project_name}",
            body_template="""Thanks {team_member_name}, this is exactly what I needed.

I'll follow up with {department} about the API docs. Keep me posted on the milestone 2 completion.

{manager_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["status", "project", "management"],
    weight=2.0,
)


TEAM_PROJECT_DISCUSSION = EmailScenario(
    id="team_project_discussion",
    name="Team Project Planning Discussion",
    description="Team discussion about project approach and priorities",
    num_participants=4,
    participant_roles=["lead", "engineer_1", "engineer_2", "pm"],
    same_department=True,
    departments=["Engineering", "IT", "Marketing"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="{quarter} Planning: {project_name}",
            body_template="""Team,

Let's align on priorities for {project_name} this quarter. Based on leadership feedback and customer requests, I see three main areas:

1. Performance improvements (critical for enterprise clients)
2. New dashboard features (most requested by users)
3. Technical debt reduction (needed for maintainability)

What are your thoughts on prioritization? I'd like to finalize our roadmap by {deadline}.

{lead_name}""",
        ),
        EmailTemplate(
            offset_hours=2.0,
            sender_index=1,
            subject_template="Re: {quarter} Planning: {project_name}",
            body_template="""I'd vote for prioritizing technical debt first, or at least in parallel with features.

The current codebase is getting harder to work with, and it's slowing down feature development. If we spend 2 weeks on cleanup, we'll move faster the rest of the quarter.

{engineer_1_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=2.5,
            sender_index=2,
            subject_template="Re: {quarter} Planning: {project_name}",
            body_template="""Agree with {engineer_1_name} on technical debt being important, but I think we need to balance it with visible progress on features.

Suggestion: Can we identify tech debt items that directly enable the dashboard features? That way we tackle both.

{engineer_2_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=3.5,
            sender_index=3,
            subject_template="Re: {quarter} Planning: {project_name}",
            body_template="""From a product perspective, the performance improvements are the most urgent. We have two enterprise deals that depend on hitting certain benchmarks.

That said, {engineer_2_name}'s suggestion makes sense. Maybe:
- Week 1-2: Performance (unblocks deals)
- Week 3-4: Tech debt that enables dashboard work
- Week 5-8: Dashboard features

Thoughts?

{pm_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=5.0,
            sender_index=0,
            subject_template="Re: {quarter} Planning: {project_name}",
            body_template="""Great discussion everyone. I like {pm_name}'s proposed sequencing.

Let's go with:
1. Performance sprint (2 weeks) - {engineer_1_name} to lead
2. Targeted tech debt (2 weeks) - {engineer_2_name} to identify items
3. Dashboard features (4 weeks) - full team

I'll update the roadmap doc and share it tomorrow. Let's sync at standup to confirm assignments.

{lead_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["planning", "project", "team", "discussion"],
    weight=1.5,
)


# =============================================================================
# ENGINEERING / TECHNICAL SCENARIOS
# =============================================================================

BUG_REPORT_THREAD = EmailScenario(
    id="bug_report_thread",
    name="Bug Report and Resolution",
    description="Bug reported, investigated, and resolved by team",
    num_participants=3,
    participant_roles=["reporter", "developer", "qa"],
    same_department=True,
    departments=["Engineering", "IT"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="[BUG] {project_name}: Critical issue in production",
            body_template="""Team,

Found a critical issue in {project_name} production:

**Description**: Users are seeing 500 errors when submitting forms

**Steps to reproduce**:
1. Go to the submission page
2. Fill out all required fields
3. Click Submit
4. Error appears

**Expected**: Form submits successfully
**Actual**: 500 Internal Server Error

**Impact**: Affecting ~15% of submissions in the last hour

Can someone investigate urgently?

{reporter_name}""",
        ),
        EmailTemplate(
            offset_hours=0.25,
            sender_index=1,
            subject_template="Re: [BUG] {project_name}: Critical issue in production",
            body_template="""Looking into this now.

{developer_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=0.75,
            sender_index=1,
            subject_template="Re: [BUG] {project_name}: Critical issue in production",
            body_template="""Found the issue.

Root cause: The last deployment included a config change that pointed to a database replica that's behind on replication. Write operations were failing.

Fix: Reverted the config change. Submissions should be working now.

{reporter_name} - can you verify from your end?

Longer term we need to add better health checks for database connections. I'll create a ticket.

{developer_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=1.0,
            sender_index=0,
            subject_template="Re: [BUG] {project_name}: Critical issue in production",
            body_template="""Confirmed - submissions are working again. Error rate back to normal.

Thanks for the quick fix {developer_name}!

{reporter_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=1.25,
            sender_index=2,
            subject_template="Re: [BUG] {project_name}: Critical issue in production",
            body_template="""I've run the regression suite and all tests pass.

Adding a test case for this scenario to prevent regression. Will also document this in the runbook.

{qa_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["bug", "engineering", "incident", "urgent"],
    weight=1.5,
    urgency="high",
)


CODE_REVIEW_REQUEST = EmailScenario(
    id="code_review_request",
    name="Code Review Request",
    description="Developer requests code review, receives feedback",
    num_participants=3,
    participant_roles=["author", "reviewer_1", "reviewer_2"],
    same_department=True,
    departments=["Engineering", "IT", "Security"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Code review: {project_name} - {file_name}",
            body_template="""Hi team,

PR ready for review: {project_name} authentication improvements

**Changes**:
- Added rate limiting to login endpoint
- Improved password validation
- Added audit logging for auth events

**Testing**:
- Unit tests added (92% coverage)
- Manual testing completed
- Load tested with 1000 concurrent requests

Please review when you get a chance. Would like to merge by {deadline}.

PR link: https://github.com/company/{project_name}/pull/1234

{author_name}""",
        ),
        EmailTemplate(
            offset_hours=4.0,
            sender_index=1,
            subject_template="Re: Code review: {project_name} - {file_name}",
            body_template="""Reviewed the PR. Looks good overall, left a few comments:

1. Line 45: Consider using a constant for the rate limit threshold
2. Line 78: The error message might leak information about valid usernames
3. Line 112: Nice use of the decorator pattern for audit logging

Approved with minor changes.

{reviewer_1_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=6.0,
            sender_index=2,
            subject_template="Re: Code review: {project_name} - {file_name}",
            body_template="""Also reviewed. Agree with {reviewer_1_name}'s comments.

One additional note:
- The rate limiting should probably be configurable per environment (different limits for staging vs prod)

Otherwise LGTM. Good security improvements.

{reviewer_2_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=7.0,
            sender_index=0,
            subject_template="Re: Code review: {project_name} - {file_name}",
            body_template="""Thanks both! Addressed all the feedback:

- Extracted rate limit to config
- Fixed the error message to be generic
- Made rate limits environment-specific

Ready for final approval when you get a chance.

{author_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["code-review", "engineering", "collaboration"],
    weight=1.5,
)


# =============================================================================
# MEETING & COORDINATION SCENARIOS
# =============================================================================

MEETING_FOLLOWUP = EmailScenario(
    id="meeting_followup",
    name="Meeting Follow-up with Action Items",
    description="Post-meeting summary shared with attendees",
    num_participants=4,
    participant_roles=["organizer", "attendee_1", "attendee_2", "attendee_3"],
    same_department=False,
    cross_department=True,
    requires_file=True,
    file_types=["docx", "pdf"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Meeting notes: {project_name} sync - {date_reference}",
            body_template="""Hi all,

Thanks for joining today's {project_name} sync. Here's a summary:

**Attendees**: {organizer_name}, {attendee_1_name}, {attendee_2_name}, {attendee_3_name}

**Discussion Points**:
- Reviewed current timeline and milestones
- Discussed resource constraints
- Aligned on next steps for stakeholder communication

**Action Items**:
- {organizer_name}: Update project plan and circulate by {deadline}
- {attendee_1_name}: Schedule follow-up with {department} team
- {attendee_2_name}: Prepare budget revision for review
- {attendee_3_name}: Draft stakeholder update email

**Next Meeting**: {meeting_day} at {meeting_time}

I've attached the detailed notes. Let me know if I missed anything.

{organizer_name}""",
            include_attachment=True,
        ),
        EmailTemplate(
            offset_hours=0.5,
            sender_index=1,
            subject_template="Re: Meeting notes: {project_name} sync - {date_reference}",
            body_template="""Thanks {organizer_name}.

One addition - we also agreed to review the competitive analysis before the next meeting. I can take the lead on that.

{attendee_1_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=1.0,
            sender_index=0,
            subject_template="Re: Meeting notes: {project_name} sync - {date_reference}",
            body_template="""Good catch, {attendee_1_name}. Updated the notes.

{organizer_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["meeting", "follow-up", "coordination"],
    weight=2.0,
)


MEETING_SCHEDULING = EmailScenario(
    id="meeting_scheduling",
    name="Meeting Scheduling",
    description="Coordinating a meeting time across multiple participants",
    num_participants=3,
    participant_roles=["organizer", "invitee_1", "invitee_2"],
    same_department=False,
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Scheduling: {project_name} review meeting",
            body_template="""Hi {invitee_1_name}, {invitee_2_name},

I'd like to schedule a meeting to review {project_name} progress and discuss next steps.

Could you share your availability for next week? I'm flexible on:
- Tuesday afternoon
- Wednesday morning
- Thursday any time

The meeting should take about an hour.

Thanks,
{organizer_name}""",
        ),
        EmailTemplate(
            offset_hours=2.0,
            sender_index=1,
            subject_template="Re: Scheduling: {project_name} review meeting",
            body_template="""Hi {organizer_name},

Tuesday afternoon or Thursday morning work best for me. Wednesday I'm in back-to-back meetings.

{invitee_1_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=3.5,
            sender_index=2,
            subject_template="Re: Scheduling: {project_name} review meeting",
            body_template="""I can do Tuesday 2-3pm or Thursday 10-11am.

{invitee_2_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=4.0,
            sender_index=0,
            subject_template="Re: Scheduling: {project_name} review meeting",
            body_template="""Perfect, let's do Tuesday 2-3pm.

I'll send a calendar invite shortly with the conference room and video link.

{organizer_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["meeting", "scheduling", "coordination"],
    weight=1.5,
)


# =============================================================================
# CROSS-DEPARTMENT SCENARIOS
# =============================================================================

CROSS_DEPT_REQUEST = EmailScenario(
    id="cross_dept_request",
    name="Cross-Department Request",
    description="Request for help/resources from another department",
    num_participants=3,
    participant_roles=["requester", "provider", "cc_manager"],
    same_department=False,
    cross_department=True,
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Request: {department} support for {project_name}",
            body_template="""Hi {provider_name},

I'm working on {project_name} and could use some support from your team.

**Request**: We need help with data analysis for the {quarter} report. Specifically:
- Customer segmentation analysis
- Revenue trend visualization
- Churn prediction model review

**Timeline**: Ideally by {deadline} for the board presentation

**Context**: This is for the quarterly business review. {cc_manager_name} can provide additional context on priorities.

Would this be something your team could help with? Happy to set up a call to discuss.

Thanks,
{requester_name}""",
            cc_indices=[2],
        ),
        EmailTemplate(
            offset_hours=5.0,
            sender_index=1,
            subject_template="Re: Request: {department} support for {project_name}",
            body_template="""Hi {requester_name},

Thanks for reaching out. We can definitely help with this.

A few questions to scope the work:
1. What data sources should we use?
2. Do you have specific metrics in mind for the segmentation?
3. Is there a template from previous quarters we should follow?

Once I have these details, I can assign someone from my team and give you a more accurate timeline.

{provider_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=6.5,
            sender_index=0,
            subject_template="Re: Request: {department} support for {project_name}",
            body_template="""Great questions, {provider_name}.

1. Primary sources are Salesforce and our data warehouse (I can provide access)
2. Key metrics: LTV, acquisition channel, product usage tiers
3. Yes, I'll share last quarter's report as a reference

I'll send over the details today. Thanks for the quick response!

{requester_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["cross-department", "request", "collaboration"],
    weight=1.5,
)


SALES_ENGINEERING_HANDOFF = EmailScenario(
    id="sales_engineering_handoff",
    name="Sales to Engineering Technical Question",
    description="Sales asks Engineering about technical capabilities for a deal",
    num_participants=3,
    participant_roles=["sales_rep", "engineer", "sales_manager"],
    same_department=False,
    cross_department=True,
    departments=["Sales", "Engineering"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Technical question: {project_name} integration for enterprise client",
            body_template="""Hi {engineer_name},

I have a potential enterprise deal that's dependent on a technical question. The client is asking about integration capabilities.

**Client question**: Can our platform integrate with their existing SAP system in real-time?

**Context**:
- This is a $500K annual deal
- They need bi-directional data sync
- Security compliance (SOC2) is required

**Timeline**: Need to respond to the client by {deadline}

CC'ing {sales_manager_name} for visibility. Can you advise on feasibility?

Thanks,
{sales_rep_name}""",
            cc_indices=[2],
        ),
        EmailTemplate(
            offset_hours=2.0,
            sender_index=1,
            subject_template="Re: Technical question: {project_name} integration for enterprise client",
            body_template="""Hi {sales_rep_name},

Good news - we can support SAP integration. Here's what I can tell the client:

**Capabilities**:
- We have a certified SAP connector (bi-directional)
- Real-time sync via webhook events, or batch sync on schedule
- Full SOC2 compliance with audit logs

**Considerations**:
- Implementation typically takes 4-6 weeks
- Will need their SAP admin involved for configuration
- Professional services engagement recommended for enterprise

I can join a technical call with the client if helpful. Let me know.

{engineer_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=2.5,
            sender_index=0,
            subject_template="Re: Technical question: {project_name} integration for enterprise client",
            body_template="""This is exactly what I needed, {engineer_name}. Thank you!

Yes, a technical call would be great. I'll set something up for this week and send an invite.

{sales_manager_name} - this should unblock the deal. I'll update the forecast.

{sales_rep_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["sales", "engineering", "cross-department", "deal"],
    weight=1.5,
)


# =============================================================================
# FILE SHARING SCENARIOS
# =============================================================================

FILE_SHARE_SIMPLE = EmailScenario(
    id="file_share_simple",
    name="Simple File Share",
    description="Quick file share with brief context",
    num_participants=2,
    participant_roles=["sender", "recipient"],
    same_department=True,
    requires_file=True,
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Sharing: {file_name}",
            body_template="""Hi {recipient_name},

Sharing {file_name} as discussed. {file_description}

Let me know if you have any questions.

{sender_name}""",
            include_attachment=True,
        ),
    ],
    tags=["share", "file", "quick"],
    weight=3.0,  # Very common
)


FILE_SHARE_TEAM = EmailScenario(
    id="file_share_team",
    name="Team File Share",
    description="Sharing a file with the team for reference",
    num_participants=4,
    participant_roles=["sender", "team_1", "team_2", "team_3"],
    same_department=True,
    requires_file=True,
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="FYI: {file_name} - {project_name}",
            body_template="""Team,

Sharing {file_name} for your reference. {file_description}

Key points:
- This is the latest version as of {date_reference}
- Please review the sections relevant to your work
- We'll discuss in our next team meeting

Feel free to reach out with questions.

{sender_name}""",
            include_attachment=True,
            recipient_indices=[1, 2, 3],
        ),
        EmailTemplate(
            offset_hours=3.0,
            sender_index=1,
            subject_template="Re: FYI: {file_name} - {project_name}",
            body_template="""Thanks for sharing {sender_name}. I'll review the section on {project_name} and follow up if needed.

{team_1_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["share", "file", "team"],
    weight=2.0,
)


# =============================================================================
# HR / ADMINISTRATIVE SCENARIOS
# =============================================================================

HR_POLICY_UPDATE = EmailScenario(
    id="hr_policy_update",
    name="HR Policy Update Announcement",
    description="HR announces policy update to team managers",
    num_participants=4,
    participant_roles=["hr_rep", "manager_1", "manager_2", "manager_3"],
    same_department=False,
    departments=["HR"],
    requires_file=True,
    file_types=["pdf", "docx"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Policy Update: {file_name}",
            body_template="""Dear Managers,

I'm writing to inform you of an update to our {file_name}.

**Summary of Changes**:
- Updated guidelines for remote work arrangements
- Clarified expense reimbursement procedures
- New section on professional development benefits

**Effective Date**: {deadline}

Please review the attached policy document and share with your teams. A brief overview session will be held {meeting_day} at {meeting_time} for any questions.

Best regards,
{hr_rep_name}
Human Resources""",
            include_attachment=True,
            recipient_indices=[1, 2, 3],
        ),
        EmailTemplate(
            offset_hours=4.0,
            sender_index=1,
            subject_template="Re: Policy Update: {file_name}",
            body_template="""Thanks {hr_rep_name}.

Quick question - for the remote work changes, does this apply to employees hired before the policy date, or only new hires?

{manager_1_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=5.0,
            sender_index=0,
            subject_template="Re: Policy Update: {file_name}",
            body_template="""Hi {manager_1_name},

Good question. The policy applies to all employees regardless of hire date. Existing remote arrangements will be grandfathered, but any changes would follow the new process.

I'll address this in the overview session as well.

{hr_rep_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["hr", "policy", "announcement"],
    weight=1.0,
)


ONBOARDING_WELCOME = EmailScenario(
    id="onboarding_welcome",
    name="New Employee Welcome",
    description="Manager welcomes new team member",
    num_participants=3,
    participant_roles=["manager", "new_hire", "buddy"],
    same_department=True,
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Welcome to the team, {new_hire_name}!",
            body_template="""Hi {new_hire_name},

Welcome to {department}! We're excited to have you join our team.

A few things to help you get started:

**First Week**
- Your onboarding buddy is {buddy_name} - they'll help you get settled
- We have a team meeting {meeting_day} at {meeting_time} where I'll introduce you
- IT should have sent your laptop and account details separately

**Key Resources**
- Team wiki: wiki.{company_domain}/{department}
- Our main project: {project_name}
- Team channel: #{department}-team on Slack

I've blocked time on your calendar for us to meet tomorrow for a 1:1.

Don't hesitate to reach out with any questions. Welcome aboard!

{manager_name}""",
            recipient_indices=[1],
            cc_indices=[2],
        ),
        EmailTemplate(
            offset_hours=1.0,
            sender_index=2,
            subject_template="Re: Welcome to the team, {new_hire_name}!",
            body_template="""Welcome {new_hire_name}!

I'm excited to be your onboarding buddy. I'll swing by your desk tomorrow morning and we can grab coffee.

A few tips from my own experience:
- The best lunch spot is the cafe on the 2nd floor
- Don't miss the Friday team social hour
- The wiki has great documentation for getting up to speed

See you tomorrow!

{buddy_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=2.0,
            sender_index=1,
            subject_template="Re: Welcome to the team, {new_hire_name}!",
            body_template="""Thank you both so much for the warm welcome!

I'm really excited to get started. {buddy_name}, coffee sounds great - I'll be at my desk by 9am.

{manager_name}, looking forward to our 1:1 tomorrow.

Thanks,
{new_hire_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["onboarding", "hr", "welcome"],
    weight=1.0,
)


# =============================================================================
# FINANCE SCENARIOS
# =============================================================================

BUDGET_APPROVAL_REQUEST = EmailScenario(
    id="budget_approval_request",
    name="Budget Approval Request",
    description="Request for budget approval with finance review",
    num_participants=3,
    participant_roles=["requester", "finance", "approver"],
    same_department=False,
    departments=["Finance"],
    requires_file=True,
    file_types=["xlsx", "pdf"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="Budget Approval Request: {project_name}",
            body_template="""Hi {finance_name},

I'm submitting a budget request for {project_name}.

**Request Summary**:
- Total Amount: $45,000
- Purpose: Software licenses and contractor support
- Timeline: {quarter}

**Business Justification**:
{file_description}

I've attached the detailed breakdown. Please let me know if you need additional information.

CC'ing {approver_name} for awareness.

Thanks,
{requester_name}""",
            include_attachment=True,
            cc_indices=[2],
        ),
        EmailTemplate(
            offset_hours=6.0,
            sender_index=1,
            subject_template="Re: Budget Approval Request: {project_name}",
            body_template="""Hi {requester_name},

Thanks for the submission. I've reviewed the request and have a few questions:

1. For the software licenses, have you compared pricing with our existing vendor agreements?
2. The contractor rate seems higher than our typical range - is there justification for the premium?
3. Can any of this be deferred to {quarter}?

Once you address these, I can fast-track approval.

{finance_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=8.0,
            sender_index=0,
            subject_template="Re: Budget Approval Request: {project_name}",
            body_template="""Good questions, {finance_name}.

1. Yes, this is through our enterprise agreement with 15% discount already applied
2. The contractor has specialized expertise in {project_name} - we've worked with them before and the quality justifies the rate
3. Unfortunately no - this is tied to the {deadline} deadline for the product launch

Happy to discuss further if needed.

{requester_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=10.0,
            sender_index=1,
            subject_template="Re: Budget Approval Request: {project_name}",
            body_template="""Thanks for the clarification. This looks reasonable.

{approver_name} - this is approved from Finance. Please confirm final sign-off.

{finance_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["finance", "budget", "approval"],
    weight=1.0,
)


# =============================================================================
# URGENT / INCIDENT SCENARIOS
# =============================================================================

SECURITY_INCIDENT = EmailScenario(
    id="security_incident",
    name="Security Incident Response",
    description="Security team responds to a potential incident",
    num_participants=3,
    participant_roles=["security", "it_admin", "manager"],
    same_department=False,
    departments=["Security", "IT"],
    urgency="critical",
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="[URGENT] Security Alert: Suspicious login activity detected",
            body_template="""SECURITY ALERT

We've detected suspicious login activity that requires immediate attention.

**Details**:
- Multiple failed login attempts from unusual IP ranges
- Affected accounts: 3 user accounts in {department}
- Timeframe: Last 2 hours
- Source IPs: Eastern Europe (unusual for our user base)

**Immediate Actions Taken**:
- Temporarily locked affected accounts
- Enabled enhanced monitoring
- Blocked source IP ranges

**Required Actions**:
- {it_admin_name}: Please verify no unauthorized access to systems
- {manager_name}: Please confirm with affected users if they recognize the activity

This could be a targeted attack. Please respond ASAP.

{security_name}
Security Team""",
        ),
        EmailTemplate(
            offset_hours=0.25,
            sender_index=1,
            subject_template="Re: [URGENT] Security Alert: Suspicious login activity detected",
            body_template="""On it. Checking access logs now.

Initial finding: No successful logins from those IPs. MFA blocked all attempts.

Will provide full report within the hour.

{it_admin_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=0.5,
            sender_index=2,
            subject_template="Re: [URGENT] Security Alert: Suspicious login activity detected",
            body_template="""Spoke with the affected users. None of them recognize the activity - they were all working from home today with normal VPN connections.

This appears to be an external attack attempt. Good catch on the early detection.

{manager_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=1.0,
            sender_index=0,
            subject_template="Re: [URGENT] Security Alert: Suspicious login activity detected",
            body_template="""Thanks both for the quick response.

**Status**: Incident contained. No evidence of successful compromise.

**Next Steps**:
- Accounts will remain locked until users complete password reset
- Will require MFA re-enrollment as precaution
- Full incident report to follow by end of day

{it_admin_name} - please schedule the password resets with affected users.
{manager_name} - please communicate to your team about the importance of reporting suspicious activity.

{security_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["security", "incident", "urgent"],
    weight=0.5,  # Less common but important
)


SYSTEM_OUTAGE = EmailScenario(
    id="system_outage",
    name="System Outage Notification",
    description="IT notifies about system outage and resolution",
    num_participants=3,
    participant_roles=["it_lead", "sysadmin", "stakeholder"],
    same_department=False,
    departments=["IT"],
    urgency="high",
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="[OUTAGE] {project_name} - Service Disruption",
            body_template="""SYSTEM ALERT

**Status**: {project_name} is currently experiencing service disruption.

**Impact**:
- Users unable to access the application
- API endpoints returning 503 errors
- Started at approximately 9:45 AM

**Affected**: All users

**Current Action**: {sysadmin_name} is investigating. Updates to follow.

{it_lead_name}
IT Operations""",
        ),
        EmailTemplate(
            offset_hours=0.25,
            sender_index=1,
            subject_template="Re: [OUTAGE] {project_name} - Service Disruption",
            body_template="""Update: Identified the issue.

Database connection pool exhausted due to a runaway query from the nightly batch job. Killing the process now and increasing pool size.

ETA to resolution: 15 minutes.

{sysadmin_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=0.5,
            sender_index=1,
            subject_template="Re: [OUTAGE] {project_name} - Service Disruption",
            body_template="""**RESOLVED**

{project_name} is back online. Users should be able to access normally now.

Root cause: Batch job query optimization needed - created ticket for permanent fix.

{sysadmin_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=0.75,
            sender_index=0,
            subject_template="Re: [OUTAGE] {project_name} - Service Disruption",
            body_template="""Thanks {sysadmin_name} for the quick resolution.

**Summary for leadership** ({stakeholder_name}):
- Outage duration: ~30 minutes
- Root cause: Database query performance issue
- Users impacted: All {project_name} users
- Permanent fix: Scheduled for next maintenance window

Post-incident review scheduled for tomorrow.

{it_lead_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["outage", "it", "incident", "urgent"],
    weight=0.5,
)


# =============================================================================
# CUSTOMER SERVICE SCENARIOS
# =============================================================================

CUSTOMER_ESCALATION = EmailScenario(
    id="customer_escalation",
    name="Customer Escalation",
    description="Support escalates issue to team for resolution",
    num_participants=3,
    participant_roles=["support_rep", "support_manager", "specialist"],
    same_department=True,
    departments=["Customer service", "Support"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="[Escalation] Priority client issue - {project_name}",
            body_template="""Hi {support_manager_name}, {specialist_name},

Escalating an issue from a priority client that needs immediate attention.

**Client**: Enterprise account (>$200K ARR)
**Issue**: Data sync failures causing business disruption
**Duration**: Client reports issue started 3 days ago
**Attempts**: Standard troubleshooting hasn't resolved

**Client Impact**:
- Unable to process daily transactions
- Executive sponsor involved and unhappy
- Renewal conversation coming up next month

This needs senior attention. Can we get someone on this today?

{support_rep_name}""",
        ),
        EmailTemplate(
            offset_hours=0.5,
            sender_index=1,
            subject_template="Re: [Escalation] Priority client issue - {project_name}",
            body_template="""Thanks for flagging, {support_rep_name}.

{specialist_name} - can you take point on this? Given the renewal timing, we need to show responsiveness.

Let's aim to have a status update for the client by end of day.

{support_manager_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=1.0,
            sender_index=2,
            subject_template="Re: [Escalation] Priority client issue - {project_name}",
            body_template="""On it. I'll reach out to the client directly within the hour to gather more details.

{support_rep_name} - can you send me the ticket history and any logs collected so far?

{specialist_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=1.25,
            sender_index=0,
            subject_template="Re: [Escalation] Priority client issue - {project_name}",
            body_template="""Sending over now. Ticket #45678.

Key notes:
- They're using v2.3 of our connector
- Issue started after they migrated their database
- Error logs show timeout exceptions

Thanks for jumping on this quickly!

{support_rep_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["escalation", "support", "customer", "urgent"],
    weight=1.0,
)


# =============================================================================
# MARKETING SCENARIOS
# =============================================================================

CAMPAIGN_REVIEW = EmailScenario(
    id="campaign_review",
    name="Marketing Campaign Review",
    description="Team reviews campaign performance and plans next steps",
    num_participants=3,
    participant_roles=["marketing_lead", "analyst", "content_manager"],
    same_department=True,
    departments=["Marketing"],
    requires_file=True,
    file_types=["pdf", "xlsx", "pptx"],
    emails=[
        EmailTemplate(
            offset_hours=0,
            sender_index=0,
            subject_template="{quarter} Campaign Performance Review",
            body_template="""Hi team,

I've compiled the {quarter} campaign performance data. Let's review and plan for next quarter.

**Summary**:
- Overall lead generation: +23% vs. previous quarter
- Email open rates: 32% (above industry average)
- Paid campaign ROI: 4.2x
- Underperforming: Social media engagement (-8%)

I've attached {file_name} with the full breakdown. {file_description}

Let's discuss in our sync {meeting_day}. Please come prepared with recommendations.

{marketing_lead_name}""",
            include_attachment=True,
        ),
        EmailTemplate(
            offset_hours=4.0,
            sender_index=1,
            subject_template="Re: {quarter} Campaign Performance Review",
            body_template="""Thanks for putting this together.

A few observations from the data:

1. The LinkedIn campaigns significantly outperformed Twitter - might want to shift more budget there
2. The webinar series drove the highest quality leads (by conversion rate)
3. Social engagement drop correlates with reduced posting frequency in month 2

I can prepare a deeper analysis on channel performance if helpful.

{analyst_name}""",
            reply_to_previous=True,
        ),
        EmailTemplate(
            offset_hours=6.0,
            sender_index=2,
            subject_template="Re: {quarter} Campaign Performance Review",
            body_template="""Good insights {analyst_name}.

On the content side:
- The case studies performed best in email campaigns
- Short-form video content had higher engagement than expected
- Blog traffic was steady but conversion needs work

For next quarter, I recommend:
- More customer success stories
- Video testimonials for social
- Gated content refresh to improve conversion

{content_manager_name}""",
            reply_to_previous=True,
        ),
    ],
    tags=["marketing", "campaign", "review", "analytics"],
    weight=1.0,
)


# =============================================================================
# COLLECT ALL SCENARIOS
# =============================================================================

BUILTIN_SCENARIOS = [
    # Document Review
    DOCUMENT_REVIEW_SIMPLE,
    DOCUMENT_REVIEW_GROUP,

    # Project & Status
    PROJECT_STATUS_UPDATE,
    TEAM_PROJECT_DISCUSSION,

    # Engineering
    BUG_REPORT_THREAD,
    CODE_REVIEW_REQUEST,

    # Meetings
    MEETING_FOLLOWUP,
    MEETING_SCHEDULING,

    # Cross-Department
    CROSS_DEPT_REQUEST,
    SALES_ENGINEERING_HANDOFF,

    # File Sharing
    FILE_SHARE_SIMPLE,
    FILE_SHARE_TEAM,

    # HR
    HR_POLICY_UPDATE,
    ONBOARDING_WELCOME,

    # Finance
    BUDGET_APPROVAL_REQUEST,

    # Urgent/Incident
    SECURITY_INCIDENT,
    SYSTEM_OUTAGE,

    # Customer Service
    CUSTOMER_ESCALATION,

    # Marketing
    CAMPAIGN_REVIEW,

]

# Mapping from burst name (in YAML) to scenario ID (loaded from JSON)
BURST_SCENARIO_MAP = {
    "project_launch": "burst_project_launch",
    "incident_response": "burst_incident_response",
    "quarter_end": "burst_quarter_end",
    "on_call_shift": "burst_on_call_handoff",
}


def get_all_scenarios() -> list:
    """Return all built-in scenarios."""
    return BUILTIN_SCENARIOS.copy()


def get_scenarios_by_tag(tag: str) -> list:
    """Return scenarios that have the specified tag."""
    return [s for s in BUILTIN_SCENARIOS if tag in s.tags]


def get_scenarios_for_department(department: str) -> list:
    """Return scenarios suitable for a department."""
    result = []
    dept_lower = department.lower()
    for s in BUILTIN_SCENARIOS:
        # Include if no department restriction or department matches
        if not s.departments:
            result.append(s)
        elif any(d.lower() == dept_lower for d in s.departments):
            result.append(s)
        elif s.cross_department:
            result.append(s)
    return result
