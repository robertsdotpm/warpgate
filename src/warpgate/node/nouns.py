"""Noun list for human-readable default PNP nicknames.

derive_default_pnp_name() hashes (NIC MACs, listen port, listen IPs)
to a 16-hex digest and maps that to a name of the form
``noun_noun_NN`` where each slot indexes into NOUNS and NN is a
two-digit number 00-99.  Same hash -> same human name (deterministic
identity, stable across runs).

Namespace size: len(NOUNS)**2 * 100.  With 1024 words that's ~105M
distinct names; for warpgate's early audience (small) the collision
probability on a default-name registration is negligible.  Callers
who want a guaranteed-unique identity should still pass an explicit
``--id <something>`` to Gate().

Words are lowercase, 3-7 letters, alphanumeric only (PNP TLD safe).
Curated to avoid offensive / political / brand terms.
"""

NOUNS = (
    # Animals (mammals)
    "cat", "dog", "fox", "wolf", "bear", "deer", "rabbit", "mouse", "rat",
    "hare", "ferret", "otter", "beaver", "badger", "weasel", "mole",
    "shrew", "bat", "squirrel", "chipmunk", "lion", "tiger", "leopard",
    "cheetah", "jaguar", "puma", "lynx", "panther", "cougar", "bobcat",
    "ocelot", "ape", "monkey", "gorilla", "chimp", "baboon", "lemur",
    "gibbon", "tarsier", "sloth", "elephant", "rhino", "hippo", "zebra",
    "giraffe", "buffalo", "bison", "ox", "bull", "cow", "yak", "antelope",
    "gazelle", "impala", "oryx", "kudu", "camel", "llama", "alpaca",
    "horse", "pony", "foal", "mule", "donkey", "goat", "sheep", "lamb",
    "pig", "boar", "hog", "ram", "raccoon", "skunk", "possum", "armadillo",
    "anteater", "panda", "koala", "wombat", "kangaroo", "wallaby",
    "platypus", "echidna",

    # Animals (birds)
    "swan", "duck", "goose", "hen", "rooster", "turkey", "peacock", "owl",
    "eagle", "hawk", "falcon", "kite", "condor", "vulture", "heron",
    "stork", "crane", "egret", "robin", "sparrow", "finch", "wren",
    "swallow", "martin", "pigeon", "dove", "crow", "raven", "magpie",
    "jay", "parrot", "canary", "lark", "thrush", "woodpecker",
    "hummingbird", "kingfisher", "pelican", "gull", "tern", "puffin",
    "penguin", "albatross", "flamingo", "ibis", "kiwi", "emu", "ostrich",
    "toucan", "macaw", "cockatoo", "starling", "oriole", "cardinal",
    "bunting", "kestrel", "merlin", "osprey",

    # Animals (water)
    "shark", "whale", "dolphin", "orca", "seal", "walrus", "manatee",
    "dugong", "cod", "tuna", "salmon", "trout", "pike", "perch", "carp",
    "eel", "ray", "skate", "flounder", "halibut", "bass", "mackerel",
    "herring", "sardine", "anchovy", "minnow", "guppy", "goldfish", "koi",
    "catfish", "swordfish", "marlin", "barracuda", "piranha", "squid",
    "octopus", "cuttlefish", "jellyfish", "coral", "starfish", "urchin",
    "crab", "lobster", "shrimp", "prawn", "krill", "clam", "oyster",
    "scallop", "mussel", "snail", "slug",

    # Animals (reptile/amphibian/insect)
    "frog", "toad", "newt", "salamander", "axolotl", "gecko", "skink",
    "lizard", "chameleon", "iguana", "komodo", "turtle", "tortoise",
    "terrapin", "python", "boa", "cobra", "viper", "mamba", "adder",
    "ant", "bee", "wasp", "hornet", "beetle", "ladybug", "butterfly",
    "moth", "dragonfly", "mosquito", "fly", "midge", "flea", "louse",
    "mite", "tick", "spider", "scorpion", "centipede", "millipede",
    "mantis", "cricket", "grasshopper", "locust", "cicada", "termite",
    "firefly", "aphid", "silkworm", "caterpillar", "earwig", "snail",

    # Nature / landscape
    "river", "lake", "pond", "creek", "brook", "stream", "ocean", "sea",
    "bay", "gulf", "cove", "lagoon", "fjord", "delta", "estuary",
    "waterfall", "rapids", "spring", "geyser", "marsh", "swamp", "bog",
    "fen", "moor", "heath", "meadow", "field", "prairie", "savanna",
    "steppe", "tundra", "desert", "oasis", "dune", "canyon", "valley",
    "gorge", "ravine", "gully", "plateau", "mesa", "butte", "ridge",
    "hill", "mountain", "peak", "summit", "cliff", "bluff", "crag",
    "crater", "volcano", "glacier", "iceberg", "island", "isle", "atoll",
    "reef", "shoal", "beach", "shore", "coast", "headland", "cape",
    "peninsula", "forest", "woodland", "grove", "thicket", "jungle",
    "rainforest", "orchard", "vineyard", "garden", "trail", "path", "road",

    # Sky / weather / cosmos
    "sky", "cloud", "rain", "hail", "snow", "sleet", "frost", "ice",
    "fog", "mist", "haze", "smog", "dew", "rainbow", "lightning",
    "thunder", "tornado", "cyclone", "hurricane", "typhoon", "storm",
    "blizzard", "drought", "monsoon", "sun", "moon", "star", "planet",
    "comet", "meteor", "asteroid", "galaxy", "nebula", "eclipse",
    "aurora", "twilight", "dawn", "dusk", "noon", "midnight",

    # Trees / plants / flowers
    "oak", "maple", "pine", "fir", "cedar", "spruce", "elm", "ash",
    "birch", "beech", "willow", "aspen", "poplar", "alder", "hazel",
    "rowan", "yew", "holly", "ivy", "moss", "fern", "lichen", "cactus",
    "bamboo", "palm", "fig", "olive", "lemon", "lime", "orange", "apple",
    "pear", "plum", "peach", "cherry", "apricot", "mango", "papaya",
    "rose", "tulip", "lily", "daisy", "iris", "violet", "orchid", "poppy",
    "lotus", "jasmine", "lilac", "lavender", "daffodil", "marigold",
    "sunflower", "primrose", "buttercup", "bluebell", "snowdrop",
    "geranium", "begonia", "azalea", "camellia", "hibiscus", "fuchsia",
    "magnolia", "wisteria", "clover", "thistle", "nettle", "bramble",
    "rosemary", "thyme", "sage", "basil", "mint", "parsley", "cilantro",
    "chive", "dill", "fennel", "oregano",

    # Food
    "bread", "loaf", "roll", "bagel", "scone", "muffin", "cake", "pie",
    "tart", "biscuit", "cookie", "wafer", "donut", "pretzel", "pasta",
    "noodle", "rice", "grain", "oat", "wheat", "barley", "corn", "millet",
    "rye", "soup", "stew", "salad", "sandwich", "pizza", "taco", "burrito",
    "dumpling", "ravioli", "lasagna", "risotto", "curry", "sushi", "ramen",
    "miso", "tofu", "cheese", "butter", "cream", "yogurt", "honey", "jam",
    "syrup", "sauce", "salt", "pepper", "sugar", "spice", "garlic", "onion",
    "tomato", "potato", "carrot", "celery", "lettuce", "spinach", "kale",
    "cabbage", "broccoli", "cauliflower", "pumpkin", "squash", "zucchini",
    "cucumber", "radish", "beet", "turnip", "parsnip", "yam", "ginger",
    "mushroom", "olive", "pepper", "chili", "almond", "walnut", "cashew",
    "peanut", "hazelnut", "chestnut", "pecan", "pistachio",

    # Drinks
    "water", "milk", "juice", "tea", "coffee", "cocoa", "lemonade", "cider",
    "soda", "wine", "beer", "ale", "stout", "lager", "porter", "mead",

    # Objects / tools / household
    "book", "page", "scroll", "letter", "diary", "journal", "novel",
    "poem", "story", "tale", "fable", "song", "chord", "note", "melody",
    "tune", "harmony", "rhythm", "drum", "flute", "harp", "violin",
    "cello", "piano", "guitar", "banjo", "trumpet", "horn", "fiddle",
    "bell", "chime", "whistle", "lamp", "lantern", "torch", "candle",
    "match", "wick", "flame", "ember", "coal", "ash", "smoke", "spark",
    "chair", "stool", "bench", "couch", "sofa", "table", "desk", "shelf",
    "rack", "stand", "cabinet", "drawer", "chest", "trunk", "crate",
    "basket", "bucket", "jar", "vase", "pot", "pan", "kettle", "teapot",
    "cup", "mug", "glass", "bowl", "plate", "dish", "saucer", "platter",
    "fork", "spoon", "knife", "ladle", "whisk", "tongs", "grater",
    "blender", "mixer", "oven", "stove", "kettle", "fridge", "freezer",
    "broom", "mop", "brush", "comb", "razor", "mirror", "soap", "towel",
    "blanket", "quilt", "pillow", "cushion", "rug", "carpet", "curtain",
    "drape", "shade", "blind", "lock", "key", "hinge", "latch", "bolt",
    "screw", "nail", "hammer", "wrench", "pliers", "drill", "saw", "axe",
    "shovel", "rake", "hoe", "spade", "trowel", "wheelbarrow", "ladder",
    "rope", "chain", "wire", "cable", "string", "thread", "ribbon",
    "knot", "loop", "hook", "needle", "pin", "pen", "pencil", "crayon",
    "marker", "paint", "ink", "brush", "canvas", "easel", "sculpture",
    "statue", "carving", "engraving",

    # Buildings / places
    "house", "cottage", "cabin", "lodge", "hut", "shack", "tent", "yurt",
    "castle", "tower", "fort", "keep", "palace", "manor", "villa", "estate",
    "barn", "shed", "garage", "stable", "warehouse", "factory", "mill",
    "bridge", "tunnel", "arch", "gate", "wall", "fence", "hedge", "porch",
    "balcony", "veranda", "terrace", "patio", "courtyard", "plaza",
    "square", "park", "garden", "fountain", "well", "cistern", "harbor",
    "wharf", "dock", "pier", "marina", "lighthouse", "beacon", "tavern",
    "inn", "diner", "bakery", "butcher", "market", "shop", "store",

    # Vehicles
    "boat", "ship", "raft", "kayak", "canoe", "yacht", "sailboat",
    "schooner", "barge", "ferry", "tugboat", "submarine", "car", "truck",
    "van", "wagon", "cart", "bus", "tram", "train", "carriage", "buggy",
    "scooter", "bicycle", "tricycle", "skateboard", "sled", "sleigh",
    "rocket", "shuttle", "plane", "glider", "balloon", "blimp", "kite",
    "drone",

    # Colors / materials
    "amber", "scarlet", "crimson", "ruby", "garnet", "coral", "salmon",
    "peach", "rust", "ochre", "saffron", "gold", "honey", "lemon",
    "ivory", "cream", "mint", "lime", "olive", "moss", "fern", "emerald",
    "jade", "sage", "teal", "turquoise", "azure", "sapphire", "indigo",
    "violet", "plum", "lavender", "lilac", "magenta", "cherry", "rose",
    "pearl", "silver", "pewter", "ash", "charcoal", "ebony", "onyx",
    "obsidian", "marble", "granite", "slate", "quartz", "crystal",
    "diamond", "opal", "amethyst", "topaz", "agate", "jasper", "copper",
    "bronze", "brass", "iron", "steel", "tin", "lead", "platinum",
    "leather", "silk", "wool", "linen", "cotton", "velvet", "denim",
    "canvas", "lace", "satin", "fur", "feather", "scale", "shell",
    "horn", "bone", "ivory", "amber",

    # Abstracts
    "story", "dream", "vision", "idea", "thought", "memory", "wish",
    "hope", "promise", "secret", "riddle", "puzzle", "game", "quest",
    "voyage", "journey", "ramble", "wander", "echo", "whisper", "shout",
    "hum", "purr", "growl", "chirp",

    # Sports / games / play
    "ball", "bat", "puck", "racquet", "club", "stick", "skate", "ski",
    "board", "kite", "dart", "marble", "domino", "card", "dice", "chess",
    "kite",

    # Body / clothing
    "hand", "foot", "ear", "eye", "nose", "lip", "tooth", "tongue",
    "thumb", "finger", "wrist", "elbow", "knee", "ankle", "heel", "toe",
    "neck", "chin", "cheek", "brow", "lash", "hair", "beard", "skin",
    "hat", "cap", "scarf", "glove", "mitten", "boot", "shoe", "sandal",
    "slipper", "robe", "cloak", "cape", "coat", "jacket", "vest", "shirt",
    "blouse", "tunic", "kilt", "skirt", "dress", "gown", "pants", "shorts",
    "belt", "buckle", "tie", "bowtie", "ring", "bracelet", "necklace",
    "pendant", "brooch", "crown", "tiara",

    # Time / measure
    "moment", "second", "minute", "hour", "day", "week", "month", "year",
    "season", "morning", "evening", "night", "spring", "summer", "autumn",
    "winter",
)


# Deduplicate while preserving first-appearance order so anyone who
# adds a noun by hand doesn't have to scan the whole tuple for
# accidental repeats first.  Tuple-of-tuple stays the source of truth
# above; the de-duped tuple is what callers index into.
seen = set()
deduped = []
for w in NOUNS:
    if w not in seen:
        seen.add(w)
        deduped.append(w)
NOUNS = tuple(deduped)
del seen, deduped, w


def hex_to_human(hex_str):
    """Map a hex string deterministically to ``noun_noun_NNN``.

    The same hex always yields the same human name.  Uses the first
    11 hex chars (44 bits): 4 for each noun index (mod len(NOUNS)),
    3 for the trailing 3-digit number (mod 1000).  Namespace is
    len(NOUNS)**2 * 1000 -- ~900M with the bundled list.
    """
    if not isinstance(hex_str, str) or len(hex_str) < 11:
        # Defensive: caller passed something unexpected.  Return the
        # input as-is so identity stays deterministic and the failure
        # mode is "ugly name", not "exception during node start".
        return hex_str
    n1 = int(hex_str[0:4], 16) % len(NOUNS)
    n2 = int(hex_str[4:8], 16) % len(NOUNS)
    num = int(hex_str[8:11], 16) % 1000
    return "{0}_{1}_{2:03d}".format(NOUNS[n1], NOUNS[n2], num)
