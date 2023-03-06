const {
  verifyTokenAndAuthorization,
  verifyTokenAndAdmin,
} = require("../middleware/verifyToken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");

const router = require("express").Router();

router.put("/:id", verifyTokenAndAuthorization, async (req, res) => {
  if (req.body.password) {
    req.body.password = await bcrypt.hash(req.body.password, 10);
  }

  const updateUser = User.findOneAndUpdate(
    req.params.id,
    {
      $set: req.body,
    },
    { new: true }
  )
    .then((user) => {
      res.status(200).json(user);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// DELERE USER
router.delete("/:id", verifyTokenAndAdmin, async (req, res) => {
  const deletedUser = await User.findByIdAndDelete(req.params.id)
    .then((deletedUser) => {
      res.status(200).json("User has been deleted...");
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// GET USER
router.get("/find/:id", verifyTokenAndAdmin, async (req, res) => {
  const user = await User.findById(req.params.id)
    .then((user) => {
      res.status(200).json({ user });
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// GET ALL USERS
router.get("/", verifyTokenAndAdmin, async (req, res) => {
  const query = req.query.new;
  const users = query
    ? await User.find()
        .sort({ createdAt: -1 })
        .limit(1)
        .then((user) => {
          res.status(200).json(user);
        })
        .catch((err) => {
          res.status(500).json(err);
        })
    : await User.find()
        .then((users) => {
          res.status(200).json(users);
        })
        .catch((err) => {
          res.status(500).json(err);
        });
});

// User Status
// router.get("/status", verifyTokenAndAdmin, (req, res) => {
//   const date = new Date();
//   console.log(date.getFullYear());
//   const lastYear = new Date(date.setFullYear(date.getFullYear() - 1));
//   console.log(lastYear);

//   try {
//     const data = User.aggregate([
//       { $match: { createdAt: { $gte: lastYear } } },
//       {
//         $project: {
//           month: { $month: "$createdAt" },
//         },
//       },
//       {
//         $group: {
//           _id: "$month",
//           total: { $sum: 1 },
//         },
//       },
//     ]);
//     res.status(200).json(data);
//   } catch (err) {
//     res.status(500).json(err);
//   }
// });

module.exports = router;
