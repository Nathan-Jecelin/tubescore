const Anthropic = require('@anthropic-ai/sdk');
const { parseDuration } = require('./youtube');

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SYSTEM_PROMPT = `You are TubeScore, an expert YouTube video analyst. You analyze video metadata, statistics, and thumbnails to give creators specific, actionable feedback to improve views and engagement.

You MUST respond with valid JSON only — no markdown, no code fences, no explanation outside the JSON.

Scoring rubric (A-F scale):

TITLE (weight: 25%)
- A: 50-60 chars, strong emotional hook or curiosity gap, power words, clear value proposition
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
- C: Basic description, few tags
- D: Minimal description, irrelevant tags
- F: Empty or spam

ENGAGEMENT (weight: 20%)
- Compare like/view ratio and comment/view ratio against benchmarks:
  - Like ratio: >5% = A, 3-5% = B, 2-3% = C, 1-2% = D, <1% = F
  - Comment ratio: >0.5% = A, 0.2-0.5% = B, 0.1-0.2% = C, 0.05-0.1% = D, <0.05% = F
- Adjust for channel size (smaller channels often have higher engagement rates)

VIDEO LENGTH (weight: 20%)
- Sweet spot for most content: 8-12 minutes
- Shorts (<60s): separate category, fine if intentional
- A: Optimal length for the apparent niche
- C: Acceptable but not ideal
- F: Way too long (>30 min for casual content) or awkward length

For each category provide:
- "grade": letter A through F
- "issues": array of 2-3 specific problems found
- "fixes": array of 2-3 actionable fixes (specific rewrites, not vague advice)

Also provide:
- "overall_grade": weighted letter grade
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

module.exports = { analyzeVideo };
