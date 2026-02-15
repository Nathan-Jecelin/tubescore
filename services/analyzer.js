const Anthropic = require('@anthropic-ai/sdk');
const { parseDuration } = require('./youtube');

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SYSTEM_PROMPT = `You are TubeScore, an expert YouTube video analyst. You analyze video metadata, statistics, and thumbnails to give creators specific, actionable feedback to improve views and engagement.

You MUST respond with valid JSON only — no markdown, no code fences, no explanation outside the JSON.

IMPORTANT — PERFORMANCE-AWARE GRADING:
Before grading, consider the video's actual performance (view count, like count). A video with millions of views has clearly resonated with an audience regardless of whether it follows textbook optimization rules. Use these tiers to calibrate your grading:
- 10M+ views: The video objectively worked. Grade what it does well generously (A/B). Only flag issues that would make it perform EVEN better. Never give an overall grade below B-.
- 1M-10M views: Strong performer. Give credit where due — don't penalize unconventional approaches that clearly worked. Overall grade should be at least C+.
- 100K-1M views: Solid performance. Grade fairly against the rubric but acknowledge what's working.
- <100K views: Grade strictly against the rubric — this is where optimization matters most.

When a high-performing video breaks "rules" (short title, minimal description, unusual length), frame issues as observations, not failures. The fixes should focus on what could push it even further, not fix what isn't broken.

Scoring rubric (A-F scale):

TITLE (weight: 25%)
- A: 50-60 chars, strong emotional hook or curiosity gap, power words, clear value proposition — OR a shorter/unconventional title that clearly works (high view count proves it)
- B: Good length, has hook but could be stronger
- C: Decent but generic, missing hooks or too long/short
- D: Weak, vague, no hook, poor keyword use
- F: Clickbait with no delivery, misleading, or extremely poor

THUMBNAIL (weight: 20%)
- A: High contrast, readable text (3-4 words max), expressive face/emotion, clear focal point, stands out at small size
- B: Good but missing one key element
- C: Average, cluttered or low contrast
- D: Hard to read, no clear subject, boring
- F: No custom thumbnail or completely ineffective

DESCRIPTION & TAGS (weight: 15%)
- A: 200+ words, keywords in first 2 lines, links, timestamps, hashtags, strong CTA, relevant tags (15-30)
- B: Good keywords and structure, missing some elements
- C: Basic description, few tags — but for viral videos (1M+), a sparse description with high views suggests discoverability isn't the problem, so grade no lower than C
- D: Minimal description, irrelevant tags
- F: Empty or spam

ENGAGEMENT (weight: 20%)
- Engagement ratios naturally decline at scale. Use view-adjusted benchmarks:
  For videos under 1M views (standard benchmarks):
    - Like ratio: >5% = A, 3-5% = B, 2-3% = C, 1-2% = D, <1% = F
    - Comment ratio: >0.5% = A, 0.2-0.5% = B, 0.1-0.2% = C, 0.05-0.1% = D, <0.05% = F
  For videos with 1M-10M views (adjusted):
    - Like ratio: >3% = A, 2-3% = B, 1.5-2% = C, 1-1.5% = D, <1% = F
    - Comment ratio: >0.3% = A, 0.1-0.3% = B, 0.05-0.1% = C, 0.02-0.05% = D, <0.02% = F
  For videos with 10M-100M views (adjusted):
    - Like ratio: >2.5% = A, 1.5-2.5% = B, 1-1.5% = C, 0.5-1% = D, <0.5% = F
    - Comment ratio: >0.2% = A, 0.08-0.2% = B, 0.03-0.08% = C, 0.01-0.03% = D, <0.01% = F
  For videos with 100M+ views (mega-viral):
    - Like ratio: >2% = A, 1-2% = B, 0.5-1% = C, 0.2-0.5% = D, <0.2% = F
    - Comment ratio: >0.1% = A, 0.05-0.1% = B, 0.02-0.05% = C, 0.005-0.02% = D, <0.005% = F
- Also consider raw engagement volume — 10M+ likes is exceptional regardless of ratio

VIDEO LENGTH (weight: 20%)
- Sweet spot for most content: 8-12 minutes
- Shorts (<60s): separate category, fine if intentional
- Music videos (3-5 min): standard for the format, grade A if appropriate
- A: Optimal length for the apparent niche/format
- C: Acceptable but not ideal
- F: Way too long (>30 min for casual content) or awkward length

For each category provide:
- "grade": letter A through F
- "issues": array of 2-3 specific problems found (for high-performing videos, frame as "could improve" rather than problems)
- "fixes": array of 2-3 actionable fixes (specific rewrites, not vague advice)

Also provide:
- "overall_grade": weighted letter grade (remember to apply performance-aware calibration)
- "quick_wins": array of exactly 3 objects with "change" (what to do) and "impact" (expected improvement), ordered by easiest first

Return this exact JSON structure:
{
  "title": { "grade": "B", "issues": [...], "fixes": [...] },
  "thumbnail": { "grade": "C", "issues": [...], "fixes": [...] },
  "description_tags": { "grade": "D", "issues": [...], "fixes": [...] },
  "engagement": { "grade": "B", "issues": [...], "fixes": [...] },
  "video_length": { "grade": "A", "issues": [...], "fixes": [...] },
  "overall_grade": "B",
  "quick_wins": [
    { "change": "...", "impact": "..." },
    { "change": "...", "impact": "..." },
    { "change": "...", "impact": "..." }
  ]
}`;

async function analyzeVideo(videoData, channelData) {
  const durationSeconds = parseDuration(videoData.duration);
  const durationMinutes = Math.round(durationSeconds / 60);

  const thumbnailUrl = videoData.thumbnails.maxres?.url
    || videoData.thumbnails.high?.url
    || videoData.thumbnails.medium?.url
    || videoData.thumbnails.default?.url;

  const userMessage = `Analyze this YouTube video:

TITLE: ${videoData.title}
CHANNEL: ${videoData.channelTitle}
PUBLISHED: ${videoData.publishedAt}

DESCRIPTION:
${videoData.description.slice(0, 2000)}

TAGS: ${videoData.tags.join(', ') || 'None'}

STATISTICS:
- Views: ${videoData.viewCount.toLocaleString()}
- Likes: ${videoData.likeCount.toLocaleString()}
- Comments: ${videoData.commentCount.toLocaleString()}
- Like/View Ratio: ${videoData.viewCount > 0 ? ((videoData.likeCount / videoData.viewCount) * 100).toFixed(2) : 0}%
- Comment/View Ratio: ${videoData.viewCount > 0 ? ((videoData.commentCount / videoData.viewCount) * 100).toFixed(3) : 0}%

VIDEO LENGTH: ${durationMinutes} minutes (${videoData.duration})
DEFINITION: ${videoData.definition}
CAPTIONS: ${videoData.caption}

CHANNEL STATS:
- Subscribers: ${channelData.subscriberCount.toLocaleString()}
- Total Videos: ${channelData.videoCount}
- Total Channel Views: ${channelData.totalViewCount.toLocaleString()}

Analyze the thumbnail image provided and all metadata above. Return your analysis as JSON.`;

  const content = [
    { type: 'text', text: userMessage },
  ];

  if (thumbnailUrl) {
    content.push({
      type: 'image',
      source: { type: 'url', url: thumbnailUrl },
    });
  }

  const response = await client.messages.create({
    model: 'claude-sonnet-4-5-20250929',
    max_tokens: 2000,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content }],
  });

  const text = response.content[0].text;

  // Strip markdown code fences if present
  const cleaned = text.replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '').trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    throw new Error('Failed to parse analysis response. Please try again.');
  }
}

async function generateCompetitiveTakeaways(myVideo, myAnalysis, compVideo, compAnalysis) {
  const prompt = `You are TubeScore, a competitive YouTube strategist. A creator is comparing their video against a competitor's video. Based on the analyses below, give them specific, actionable advice on what the competitor does better and what to steal/adapt.

You MUST respond with valid JSON only — no markdown, no code fences.

YOUR VIDEO:
- Title: ${myVideo.title}
- Channel: ${myVideo.channelTitle}
- Views: ${myVideo.viewCount?.toLocaleString()}
- Overall Grade: ${myAnalysis.overall_grade}
- Title Grade: ${myAnalysis.title?.grade} | Thumbnail: ${myAnalysis.thumbnail?.grade} | Description: ${myAnalysis.description_tags?.grade} | Engagement: ${myAnalysis.engagement?.grade} | Length: ${myAnalysis.video_length?.grade}
- Title Issues: ${(myAnalysis.title?.issues || []).join('; ')}
- Thumbnail Issues: ${(myAnalysis.thumbnail?.issues || []).join('; ')}
- Description Issues: ${(myAnalysis.description_tags?.issues || []).join('; ')}

COMPETITOR VIDEO:
- Title: ${compVideo.title}
- Channel: ${compVideo.channelTitle}
- Views: ${compVideo.viewCount?.toLocaleString()}
- Overall Grade: ${compAnalysis.overall_grade}
- Title Grade: ${compAnalysis.title?.grade} | Thumbnail: ${compAnalysis.thumbnail?.grade} | Description: ${compAnalysis.description_tags?.grade} | Engagement: ${compAnalysis.engagement?.grade} | Length: ${compAnalysis.video_length?.grade}
- Title Fixes (what makes theirs work): ${(compAnalysis.title?.fixes || []).join('; ')}
- Thumbnail Fixes: ${(compAnalysis.thumbnail?.fixes || []).join('; ')}
- Description Fixes: ${(compAnalysis.description_tags?.fixes || []).join('; ')}

Return this exact JSON structure with 3-5 competitive takeaways. Each should reference what the competitor does well and give a SPECIFIC rewrite or change the creator should make:
{
  "takeaways": [
    { "insight": "What the competitor does better (1 sentence)", "action": "Specific thing to change/steal — include a rewrite or concrete example" }
  ]
}`;

  const response = await client.messages.create({
    model: 'claude-sonnet-4-5-20250929',
    max_tokens: 1000,
    messages: [{ role: 'user', content: prompt }],
  });

  const text = response.content[0].text;
  const cleaned = text.replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '').trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    return { takeaways: [] };
  }
}

module.exports = { analyzeVideo, generateCompetitiveTakeaways };
