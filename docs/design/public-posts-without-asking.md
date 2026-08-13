# Reading someone's public posts without telling them you did

Status: design accepted, not implemented. Closes the peer-visible half of the profile-view
leak; the relay-visible half was closed earlier by padding.

## What leaks today

Visiting a profile you do not subscribe to sends the author a `PostsRequest` over a
session. They answer with their public posts. So the author learns **who looked and when**,
and only online authors can be looked at.

Subscribers do not have this problem: posts are already fanned out to them E2E, so reading
one is a local act. The gap is exactly the non-subscriber — someone deciding whether to
follow, which is the moment the reader would most like not to announce.

## The shape of the fix

The author stops being asked. Instead they periodically publish a **public posts bundle**
to a drop-box a visitor can compute, and a visit becomes an ordinary fetch.

    box      = H("karst-public-posts-v1" ‖ author_ik ‖ relay_id)
    key      = H("karst-public-posts-key-v1" ‖ author_ik)
    bundle   = seal(key, recent public posts)

Both derive from the author's identity key, which a visitor already has — it is what they
typed or scanned to get here. Nothing new travels, and there is no second thing an author
can forget to publish.

The key being derivable by anyone who can address the author is not a weakness, it is the
requirement: these are the posts the author chose to make public. What it must NOT be is
derivable by someone who does not know the identity key, which is why the box is derived
rather than published.

The box depends on the relay for the same reason ordinary drop-boxes do: so the same author
does not present the same address to two relays that could be compared.

## What this buys, exactly

- **The author learns nothing about a visit.** No message reaches them, so there is nothing
  to correlate — not who, not when, not how often.
- **Offline authors can be read.** Today an author who is not online cannot be looked at.
- **A visit costs one fetch.** It is the same operation as checking mail, against the same
  endpoint, in the same size class.

## What it does not buy

- **The relay still sees a fetch.** It sees fetches constantly and cannot tell this one from
  mail — the padding work already made profile reads indistinguishable at the relay — but
  "the relay learns nothing" is not the claim. It learns that a box was read.
- **The author still controls the content.** They decide what goes in the bundle and when it
  is refreshed, so a stale bundle is a stale profile. That is a freshness cost, not a
  privacy one, and it is the trade being made: a live answer is fresh and observed, a
  published bundle is stale and unobserved.
- **Bundle publication is itself a deposit.** The relay sees the author deposit on a
  schedule. That says the author has public posts, which their profile says anyway.

## Rules the implementation must keep

**The bundle is a size class, not a size.** A bundle padded to its content tells the relay
how much the author has published. It goes in the same fixed classes as everything else.

**Refresh is on a schedule, not on write.** Republishing the moment a post is added ties a
deposit to an authoring action, which is a timing signal about the author. The schedule
makes deposits regular and uninformative — the same reasoning as scheduled send.

**A missing bundle is not an error.** An author who has never published one, or whose
bundle expired, is indistinguishable from one who has no public posts. The visitor shows an
empty profile either way and does not fall back to asking, because a fallback that asks is
the leak coming back through the error path.

**The live pull is removed, not kept as a fallback.** Leaving `PostsRequest` in place "for
when the bundle is missing" would preserve exactly the behaviour this removes, and it would
fire precisely for the authors who publish least.
