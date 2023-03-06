const {
  verifyTokenAndAuthorization,
  verifyToken,
  verifyTokenAndAdmin,
} = require("../middleware/verifyToken");
const Order = require("../models/Order");

const router = require("express").Router();

//CREATE CART
router.post("/", verifyToken, (req, res) => {
  return Order.create(req.body)
    .then((order) => {
      res.status(201).json(order);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// UPDATE ORDER
router.put("/:id", verifyTokenAndAdmin, (req, res) => {
  return Order.findByIdAndUpdate(
    req.params.id,
    {
      $set: req.body,
    },
    { new: true }
  )
    .then(() => {
      res.status(200).json("Order Updated Successfuly");
    })
    .catch((err) => {
      res.status(500).json("Order Updated Failed");
    });
});

// //DELETE ORDER
router.delete("/:id", verifyTokenAndAdmin, (req, res) => {
  return Order.findByIdAndDelete(req.params.id)
    .then(() => {
      res.status(200).json("Order Deleted Successfuly");
    })
    .catch((err) => {
      res.status(500).json("Order Deleted Failed");
    });
});

// GET USER ORDERS
router.get("/find/:userId", verifyTokenAndAuthorization, (req, res) => {
  return Order.findOne({ userId: req.params.userId })
    .then((orders) => {
      res.status(200).json(orders);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// GET ALL
router.get("/", verifyTokenAndAdmin, (req, res) => {
  return Order.find()
    .then((orders) => {
      res.status(200).json(orders);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// GET ORDER STATUS
router.get("/income", verifyTokenAndAdmin, (req, res) => {
  const date = new Date();
  const lastMonth = new Date(date.setMonth(date.getMonth() - 1));
  const previousMonth = new Date(date.setMonth(lastMonth.getMonth() - 1));
  return Order.aggregate([
    {
      $match: {
        createdAt: {
          $gte: previousMonth,
        },
      },
    },
    {
      $project: {
        month: {
          $month: "$createdAt",
        },
        sales: "$amount",
      },
    },
    {
      $group: {
        _id: "$month",
        total: { $sum: "$sales" },
      },
    },
  ])
    .then((sales) => {
      res.status(200).json(sales);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

module.exports = router;
